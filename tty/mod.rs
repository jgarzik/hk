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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

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
use crate::io::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::task::pid::Pid;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

// Re-export commonly used types
pub use serial_core::SerialStruct;
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
pub use termios::{KTermios, Termios, Winsize};

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

    /// The line discipline is nearly full: ask the sender to pause
    /// (Linux tty_operations.throttle; a UART sends STOP under IXOFF)
    fn throttle(&self, tty: &Tty) {
        let _ = tty;
    }

    /// There is room again (Linux tty_operations.unthrottle; a UART
    /// sends START under IXOFF)
    fn unthrottle(&self, tty: &Tty) {
        let _ = tty;
    }

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

    /// Bring the port up at an open of a port that is not (Linux
    /// tty_port_operations.activate, uart_port_activate), under the
    /// tty's `port`: true if up; false if not but the open goes on, the
    /// tty's I/O failing (Linux's 1: a port of unknown type, or one
    /// that did not start for CAP_SYS_ADMIN, `admin`); else the error
    /// the open fails with
    fn activate(&self, admin: bool) -> Result<bool, KernelError> {
        let _ = admin;
        Ok(true)
    }

    /// A hangup with no /dev/console file open (Linux uart_hangup,
    /// uart_shutdown), under the tty's `port`: queued output is dropped
    /// and its buffer freed; `up`: the port was up, and now goes down
    fn hangup(&self, up: bool) {
        let _ = up;
    }

    /// The port's device goes (true) or comes back (false), under the
    /// tty's `port` (Linux uart_state.uart_port)
    fn detach(&self, gone: bool) {
        let _ = gone;
    }

    /// The tty's last close (Linux tty_port_shutdown), under the tty's
    /// `port`: `down`, the port was up and is not a console
    /// (port->console), so it goes down and its output buffer is freed
    /// (uart_tty_port_shutdown); either way the tty's flow control
    /// state goes with the tty
    fn shutdown(&self, down: bool) {
        let _ = down;
    }

    /// The console write (Linux console->write): bytes straight to the
    /// hardware, LF as CR LF, then a wait until the transmitter is
    /// empty. A UART takes its port lock (`serial_core::UartPort`)
    fn console_write(&self, data: &[u8]);

    /// TIOCGSERIAL (Linux tty_operations.get_serial), under the tty's
    /// `port`: ENOTTY if the driver has none
    fn get_serial(&self, port: &TtyPort) -> Result<SerialStruct, KernelError> {
        let _ = port;
        Err(KernelError::NotTty)
    }

    /// TIOCSSERIAL (Linux tty_operations.set_serial), under the tty's
    /// `port`; `users`: the port's opens (0: hung up, not active)
    fn set_serial(
        &self,
        tty: &Tty,
        port: &mut TtyPort,
        ss: &SerialStruct,
        users: usize,
    ) -> Result<(), KernelError> {
        let _ = (tty, port, ss, users);
        Err(KernelError::NotTty)
    }
}

/// A port's state (Linux struct tty_port: close_delay and
/// closing_wait in ticks, set by TIOCSSERIAL; the initialized flag)
pub struct TtyPort {
    /// The port is up: from the open that activated it to the close,
    /// hangup or port move that took it down (Linux
    /// TTY_PORT_INITIALIZED)
    pub initialized: bool,
    /// Delay after a close with an open waiting for carrier (Linux
    /// tty_port_close_end; hk has no blocked opens, so it is only kept)
    pub close_delay: u32,
    /// How long a last close waits for output to drain; 0 for as long
    /// as it takes (ASYNC_CLOSING_WAIT_INF), ASYNC_CLOSING_WAIT_NONE
    /// for not at all
    pub closing_wait: u32,
}

impl TtyPort {
    /// Linux tty_port_init: close_delay 0.5 s, closing_wait 30 s
    const fn new() -> Self {
        Self {
            initialized: false,
            close_delay: (50 * 1000 / 100 / crate::task::percpu::TICK_MS) as u32,
            closing_wait: (3000 * 1000 / 100 / crate::task::percpu::TICK_MS) as u32,
        }
    }
}

/// A tty's open files (Linux tty->count and tty_files) and its port's
/// opens (Linux port->count: not those a hangup took away)
struct TtyFiles {
    list: Vec<Arc<Redirect>>,
    port_count: usize,
    /// Hung up, not opened since (Linux TTY_HUPPED)
    hupped: bool,
}

impl TtyFiles {
    const fn new() -> Self {
        Self {
            list: Vec::new(),
            port_count: 0,
            hupped: false,
        }
    }
}

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
    pub termios: Mutex<KTermios>,
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
    /// The driver is throttled (Linux TTY_THROTTLED under
    /// throttle_mutex)
    throttle: crate::sync::Mutex<bool>,
    /// A last close is draining output: input only does flow control
    /// (Linux tty->closing)
    closing: AtomicBool,
    /// A write could not finish with O_ASYNC files listening: the next
    /// wakeup sends them SIGIO (Linux TTY_DO_WRITE_WAKEUP)
    do_write_wakeup: AtomicBool,
    /// That SIGIO is due from an interrupt handler: the flip thread
    /// sends it
    wakeup_due: AtomicBool,
    /// Open files and the port's opens (Linux tty_lock: tty->count,
    /// tty_files, port->count): held across an open, a release (the
    /// port's last close drains output) and a hangup
    files: crate::sync::Mutex<TtyFiles>,
    /// Exclusive mode: a reopen without CAP_SYS_ADMIN is EBUSY (Linux
    /// TTY_EXCLUSIVE, TIOCEXCL); set and cleared by ioctl with no lock,
    /// tested by an open and cleared by the last release under `files`
    exclusive: AtomicBool,
    /// A hangup is under way: readers stop (Linux TTY_HUPPING)
    hupping: AtomicBool,
    /// The port is down or failed to come up: read, write and the
    /// hardware ioctls fail with EIO (Linux TTY_IO_ERROR); an open of
    /// a port that is down clears it, as does the last release (Linux
    /// frees the tty_struct)
    io_error: AtomicBool,
    /// Port state (Linux tty_port, under port->mutex)
    port: crate::sync::Mutex<TtyPort>,
}

impl Tty {
    /// Create a new TTY with the given driver (const fn for static init)
    pub const fn new(name: &'static str, dev: DevId, driver: &'static dyn TtyDriver) -> Self {
        Self {
            name,
            dev,
            termios: Mutex::new(KTermios::from_termios(Termios::cooked())),
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
            throttle: crate::sync::Mutex::new(false),
            closing: AtomicBool::new(false),
            do_write_wakeup: AtomicBool::new(false),
            wakeup_due: AtomicBool::new(false),
            files: crate::sync::Mutex::new(TtyFiles::new()),
            exclusive: AtomicBool::new(false),
            hupping: AtomicBool::new(false),
            io_error: AtomicBool::new(false),
            port: crate::sync::Mutex::new(TtyPort::new()),
        }
    }

    /// Mark the tty's I/O failing or not (Linux TTY_IO_ERROR)
    pub fn set_io_error(&self, on: bool) {
        self.io_error.store(on, Ordering::Release);
    }

    /// The tty's I/O fails (Linux tty_io_error)
    pub fn io_error(&self) -> bool {
        self.io_error.load(Ordering::Acquire)
    }

    /// Set or clear exclusive mode (Linux TIOCEXCL, TIOCNXCL)
    pub fn set_exclusive(&self, on: bool) {
        self.exclusive.store(on, Ordering::Release);
    }

    /// In exclusive mode (Linux TIOCGEXCL)
    pub fn exclusive(&self) -> bool {
        self.exclusive.load(Ordering::Acquire)
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

    /// Stop output (Linux stop_tty): a STOP character under IXON
    pub(crate) fn stop_tty(&self) {
        let mut f = self.flow.lock();
        self.stop_locked(&mut f);
    }

    /// Restart output unless TCOOFF holds it, waking writers (Linux
    /// start_tty)
    pub(crate) fn start_tty(&self) {
        let wake = {
            let mut f = self.flow.lock();
            self.start_locked(&mut f)
        };
        if wake {
            self.write_wakeup();
        }
    }

    /// Output is stopped, not by TCOOFF (IXANY's test: Linux
    /// flow.stopped && !flow.tco_stopped)
    pub(crate) fn stopped_by_input(&self) -> bool {
        let f = self.flow.lock();
        f.stopped && !f.tco_stopped
    }

    /// Throttle the driver once (Linux tty_throttle_safe)
    pub(crate) fn throttle(&self) {
        let mut th = self.throttle.lock();
        if !*th {
            *th = true;
            self.driver.throttle(self);
        }
    }

    /// Unthrottle a throttled driver (Linux tty_unthrottle_safe)
    pub(crate) fn unthrottle(&self) {
        let mut th = self.throttle.lock();
        if *th {
            *th = false;
            self.driver.unthrottle(self);
        }
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

    /// Sleep until the driver takes `n` bytes or `hung` (Linux
    /// n_tty_write's wait on write_wait): EAGAIN if `nonblock`,
    /// ERESTARTSYS on a signal
    pub fn wait_room(
        &self,
        n: usize,
        nonblock: bool,
        hung: &dyn Fn() -> bool,
    ) -> Result<(), KernelError> {
        if self.write_room() >= n {
            return Ok(());
        }
        if nonblock {
            return Err(KernelError::WouldBlock);
        }
        self.write_wait
            .wait_event_interruptible(|| self.write_room() >= n || hung())
    }

    /// A hangup is under way (Linux TTY_HUPPING)
    pub(crate) fn hupping(&self) -> bool {
        self.hupping.load(Ordering::Acquire)
    }

    // =========================================================================
    // Methods for ioctl support
    // =========================================================================

    /// Get a copy of the termios structure
    pub fn get_termios(&self) -> KTermios {
        *self.termios.lock()
    }

    /// Set the termios structure
    pub fn set_termios(&self, termios: KTermios) {
        self.update_termios(|t| *t = termios);
    }

    /// Change termios in place (Linux: under termios_rwsem). Under
    /// ldata, so input, reads and polls see the old settings or the new
    /// ones with the ICANON change applied, never half; readers and
    /// pollers are woken (VMIN, VTIME or ICANON may make input readable)
    pub fn update_termios(&self, f: impl FnOnce(&mut KTermios)) {
        let mut ld = n_tty::ldata(self);
        let (canon, ixon_off) = {
            let mut t = self.termios.lock();
            let old = t.c_iflag;
            f(&mut t);
            (
                t.c_lflag & termios::ICANON != 0,
                old & IXON != 0 && t.c_iflag & IXON == 0,
            )
        };
        ld.set_icanon(canon);
        // Linux n_tty_set_termios: output stopped by STOP restarts once
        // IXON is cleared (not output stopped by TCOOFF)
        if ixon_off && !self.flow.lock().tco_stopped {
            self.start_tty();
            n_tty::process_echoes(self, &mut ld);
        }
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
        if let Some(r) = file.private_ref::<Redirect>() {
            r.file
                .store(core::ptr::from_ref(file).cast_mut(), Ordering::Release);
        }
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

    /// A file opened the tty (Linux tty_open: tty_reopen's tty->count,
    /// tty_add_file, the port's open, TTY_HUPPED cleared, under
    /// tty_lock); then it may become the controlling tty. In exclusive
    /// mode a reopen, by any path, needs CAP_SYS_ADMIN (Linux
    /// tty_reopen: EBUSY), the file left unlisted and not pointed at
    /// the tty. A listed file is pointed at it: a later failure (the
    /// activation) fails the open, and the file's release undoes it
    /// (Linux tty_open's tty_release)
    fn opened(&self, r: Arc<Redirect>, file: &File, via: Via) -> Result<(), KernelError> {
        let tty = r.tty;
        let mut f = self.files.lock();
        if !f.list.is_empty()
            && self.exclusive()
            && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
        {
            return Err(KernelError::Busy);
        }
        let any: Arc<dyn core::any::Any + Send + Sync> = r.clone();
        file.private.call_once(|| any);
        f.list.push(r);
        f.port_count += 1;
        self.port_open()?;
        f.hupped = false;
        if via == Via::Node && file.get_flags() & O_NOCTTY == 0 {
            jobctrl::open_set_tty(tty, file);
        }
        Ok(())
    }

    /// The port's part of an open (Linux tty_port_open): a port that is
    /// not up is brought up, the tty's I/O error cleared first (and set
    /// again if it does not come up); under `files`
    fn port_open(&self) -> Result<(), KernelError> {
        let mut port = self.port.lock();
        if port.initialized {
            return Ok(());
        }
        self.set_io_error(false);
        let admin = crate::task::capable(crate::task::CAP_SYS_ADMIN);
        match self.driver.activate(admin) {
            Ok(true) => {
                port.initialized = true;
                Ok(())
            }
            // Linux uart_open: tty_port_open's 1 is a successful open
            Ok(false) => {
                self.set_io_error(true);
                Ok(())
            }
            Err(e) => {
                self.set_io_error(true);
                Err(e)
            }
        }
    }

    /// A file of the tty is released (Linux tty_release). The port's
    /// last open closes it (uart_close -> tty_port_close), unless a
    /// hangup took this file's open away; the tty's last file makes it
    /// start afresh, as Linux frees the tty_struct: flow control, the
    /// write wakeup, input and the controlling session go; termios
    /// stays (the driver's saved termios)
    fn release(&self, r: &Arc<Redirect>) {
        let mut f = self.files.lock();
        f.list.retain(|x| !Arc::ptr_eq(x, r));
        if !r.hung.load(Ordering::Acquire) && f.port_count > 0 {
            f.port_count -= 1;
            if f.port_count == 0 {
                self.close_port();
            }
        }
        if !f.list.is_empty() {
            return;
        }
        f.hupped = false;
        self.set_io_error(false);
        self.set_exclusive(false);
        jobctrl::session_clear_tty(self);
        *self.flow.lock() = Flow {
            stopped: false,
            tco_stopped: false,
        };
        self.do_write_wakeup.store(false, Ordering::Release);
        self.wakeup_due.store(false, Ordering::Release);
        *self.throttle.lock() = false;
        self.closing.store(false, Ordering::Release);
    }

    /// The port's last close (Linux tty_port_close_start,
    /// tty_port_shutdown): output stopped by TCOOFF is dropped, the
    /// rest drains for up to closing_wait (none: not at all; 0: as long
    /// as it takes), input is dropped, then the port shuts down unless
    /// it is a console
    fn close_port(&self) {
        self.closing.store(true, Ordering::Release);
        let tco = self.flow.lock().tco_stopped;
        if tco {
            self.flush_output();
        }
        let wait = self.port.lock().closing_wait;
        if wait != u32::from(serial_core::ASYNC_CLOSING_WAIT_NONE) {
            self.wait_until_sent(u64::from(wait));
        }
        self.flush_input();
        let console = crate::console::console_ttys()
            .iter()
            .flatten()
            .any(|t| core::ptr::eq(*t, self));
        let mut port = self.port.lock();
        let down = !console && port.initialized;
        if down {
            port.initialized = false;
        }
        self.driver.shutdown(down);
        if !console {
            self.set_io_error(true);
        }
    }

    /// The port's device goes (Linux serial_core_remove_one_port,
    /// after the hangup and unregister_console): a port still up, kept
    /// so by /dev/console files a hangup leaves alone, goes down
    /// without a tty (uart_shutdown(NULL)): those files' writes take
    /// nothing from now on, and their I/O error is not set
    pub fn port_remove(&self) {
        let mut port = self.port.lock();
        if core::mem::replace(&mut port.initialized, false) {
            self.driver.hangup(true);
        }
        // Linux state->uart_port = NULL: opens ENXIO, TIOCSSERIAL EIO,
        // TIOCGSERIAL ENODEV from now on
        self.driver.detach(true);
    }

    /// The port's device comes (again) (Linux serial_core_add_one_port:
    /// state->uart_port set under port->mutex)
    pub fn port_add(&self) {
        let _port = self.port.lock();
        self.driver.detach(false);
    }

    /// TIOCGSERIAL (Linux tty_tiocgserial)
    pub fn get_serial(&self) -> Result<SerialStruct, KernelError> {
        self.driver.get_serial(&self.port.lock())
    }

    /// TIOCSSERIAL (Linux tty_set_serial -> uart_set_info_user): under
    /// the files (Linux tty_port_users under port->mutex), ldata
    /// (termios_rwsem, write) and the port mutex
    pub fn set_serial(&self, ss: &SerialStruct) -> Result<(), KernelError> {
        let f = self.files.lock();
        let _ld = n_tty::ldata(self);
        let mut port = self.port.lock();
        self.driver.set_serial(self, &mut port, ss, f.port_count)
    }

    /// Hang the tty up (Linux __tty_hangup; `exit_session`: its session
    /// leader is exiting, tty_vhangup_session). Its files but those of
    /// /dev/console become hung up (Linux hung_up_tty_fops: read 0,
    /// write EIO, poll POLLHUP, ioctl EIO) and leave the O_ASYNC list;
    /// the session leader gets SIGHUP and SIGCONT (and with
    /// `exit_session` the foreground group SIGHUP); input and output
    /// are flushed and the line discipline starts afresh; the tty has
    /// no session any more. With a /dev/console file open the port
    /// stays open (Linux closes it once per hung file), else it is hung
    /// up (uart_hangup) and has no opens left
    pub fn hangup(&self, exit_session: bool) {
        let mut f = self.files.lock();
        // Not open (Linux: no tty_struct to hang up), or hung up and
        // not opened since (TTY_HUPPED)
        if f.list.is_empty() || f.hupped {
            return;
        }
        self.hupping.store(true, Ordering::Release);
        let (mut cons, mut closecount) = (false, 0);
        for r in &f.list {
            if r.console {
                cons = true;
                continue;
            }
            if r.hung.swap(true, Ordering::AcqRel) {
                continue;
            }
            closecount += 1;
            r.fasync_off(self);
        }
        let (session, pgrp) = jobctrl::hangup_take(self);
        jobctrl::signal_session_leader(self, session, pgrp, exit_session);
        // Linux tty_ldisc_hangup: the line discipline's and the
        // driver's buffers flushed, a pending write wakeup run, readers
        // and writers woken, the line discipline reset (reinit or kill)
        self.flush_input();
        self.driver.flush_buffer();
        if self.do_write_wakeup.load(Ordering::Acquire) {
            self.ldisc_write_wakeup();
        }
        self.write_wait.wake_all();
        self.read_wait.wake_all();
        n_tty::ldata(self).reinit();
        *self.throttle.lock() = false;
        self.do_write_wakeup.store(false, Ordering::Release);
        self.wakeup_due.store(false, Ordering::Release);
        if cons {
            f.port_count = f.port_count.saturating_sub(closecount);
        } else {
            // Linux uart_hangup -> uart_shutdown(tty), tty_port_hangup
            let mut port = self.port.lock();
            self.set_io_error(true);
            let up = core::mem::replace(&mut port.initialized, false);
            self.driver.hangup(up);
            drop(port);
            f.port_count = 0;
        }
        f.hupped = true;
        self.hupping.store(false, Ordering::Release);
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

    /// A background reader gets SIGTTIN (Linux job_control); a hung up
    /// file reads end of file (Linux hung_up_tty_read)
    fn read(&self, file: &File, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        if tty_hung_up_p(file) {
            return Ok(0);
        }
        // Linux tty_read
        if self.io_error() {
            return Err(KernelError::Io);
        }
        jobctrl::check_change(self, crate::signal::SIGTTIN)?;
        n_tty::read(self, file, to)
    }

    /// Under the write lock to the end (Linux iterate_tty_write); with
    /// TOSTOP a background writer gets SIGTTOU (Linux n_tty_write); a
    /// hung up file EIO (Linux hung_up_tty_write)
    fn write(&self, file: &File, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        // Linux hung_up_tty_write, file_tty_write
        if tty_hung_up_p(file) || self.io_error() {
            return Err(KernelError::Io);
        }
        let _writer = self.lock_write(file)?;
        if self.get_termios().c_lflag & TOSTOP != 0 {
            jobctrl::check_change(self, crate::signal::SIGTTOU)?;
        }
        let nonblock = file.get_flags() & crate::fs::flags::O_NONBLOCK != 0;
        n_tty::write(self, from, nonblock, &|| tty_hung_up_p(file))
    }

    /// A hung up file: ENOTTY for TIOCSPGRP, else EIO (Linux
    /// hung_up_tty_ioctl)
    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        if tty_hung_up_p(file) {
            return Err(if cmd == ioctl::TIOCSPGRP {
                KernelError::NotTty
            } else {
                KernelError::Io
            });
        }
        ioctl::tty_ioctl(self, file, cmd, arg)
    }

    /// A hung up file: ENOTTY (Linux hung_up_tty_fasync)
    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        if tty_hung_up_p(file) {
            return Some(Err(KernelError::NotTty));
        }
        Some(self.tty_fasync(file, fd, on))
    }

    /// Writable while the driver has room and little queued (Linux
    /// n_tty_poll); a hung up file is everything (Linux
    /// hung_up_tty_poll)
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        if tty_hung_up_p(file) {
            return POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM;
        }
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

/// How a file reached its tty (Linux tty_open)
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// The tty's own node (tty_open_by_driver): it may become the
    /// controlling tty
    Node,
    /// /dev/console (tty_open_by_driver via console_device): a hangup
    /// leaves the file be
    Console,
    /// /dev/tty, the controlling tty (tty_open_current_tty)
    Current,
}

/// An open file of a tty, its private data (Linux points the file at
/// the tty, tty_file_private): listed on the tty (`TtyFiles`) from its
/// open to its release
struct Redirect {
    tty: &'static Tty,
    /// Opened through /dev/console (Linux redirected_tty_write): a
    /// hangup leaves it be
    console: bool,
    /// Hung up (Linux f_op = hung_up_tty_fops): set under `Tty.files`
    hung: AtomicBool,
    /// The file, recorded by its first fasync call (the file is in its
    /// final place by then), for a hangup to take it off the O_ASYNC
    /// list; null if it never armed
    file: AtomicPtr<File>,
}

impl Redirect {
    /// The tty `file` was pointed at
    fn tty(file: &File) -> Result<&'static Tty, KernelError> {
        file.private_ref::<Redirect>()
            .map(|r| r.tty)
            .ok_or(KernelError::Io)
    }

    /// Open `tty` through `file`: list the file on the tty and point
    /// it there (Linux tty->count, tty_add_file), reached `via` its
    /// node, /dev/console or /dev/tty. The release of a file whose
    /// open failed before it was listed finds nothing to drop; one
    /// that failed later drops it as any release
    fn open(file: &File, tty: &'static Tty, via: Via) -> Result<(), KernelError> {
        let r = try_arc(Redirect {
            tty,
            console: via == Via::Console,
            hung: AtomicBool::new(false),
            file: AtomicPtr::new(core::ptr::null_mut()),
        })?;
        tty.opened(r, file, via)
    }

    /// The release of a file opened by `open` (Linux tty_release)
    fn release(file: &File) {
        if let Some(r) = file.private_arc::<Redirect>() {
            r.tty.release(&r);
        }
    }

    /// Take the file off `tty`'s O_ASYNC list (Linux __tty_hangup's
    /// __tty_fasync(-1, filp, 0)), under `Tty.files`
    fn fasync_off(&self, tty: &Tty) {
        let p = self.file.load(Ordering::Acquire);
        if p.is_null() {
            return;
        }
        // SAFETY: `p` is this file's address, taken in its fasync call
        // (made on the file in its final allocation); the file's
        // release unlists this Redirect under `Tty.files`, which the
        // caller holds with it listed, so the file is not yet released
        // and its memory is live
        let file = unsafe { &*p };
        let _ = fasync_helper(&tty.fasync, file, -1, false);
    }
}

/// The file was hung up (Linux tty_hung_up_p)
pub(crate) fn tty_hung_up_p(file: &File) -> bool {
    file.private_ref::<Redirect>()
        .is_some_and(|r| r.hung.load(Ordering::Acquire))
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
        Redirect::open(file, self.0, Via::Node)
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

/// vhangup(2): hang up the caller's controlling tty, if any (Linux
/// tty_vhangup_self); EPERM without CAP_SYS_TTY_CONFIG
pub fn sys_vhangup() -> crate::util::error::KernelResult<()> {
    use crate::task::{CAP_SYS_TTY_CONFIG, capable};
    if !capable(CAP_SYS_TTY_CONFIG) {
        return Err(KernelError::NotPermitted);
    }
    if let Some(tty) = jobctrl::current_tty() {
        tty.hangup(false);
    }
    Ok(())
}

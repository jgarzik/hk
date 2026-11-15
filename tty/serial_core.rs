//! UART core (Linux drivers/tty/serial/serial_core.c): a port's lock
//! and transmit circular buffer
//!
//! A tty write copies into the port's transmit buffer under the port
//! lock and starts the transmitter (Linux uart_write -> start_tx); the
//! TX interrupt drains it a FIFO's worth at a time (Linux
//! serial8250_tx_chars, pl011_tx_chars), or a timer for a port without
//! an interrupt (Linux serial8250_timeout), and wakes the tty's writers
//! once it runs low (uart_write_wakeup, WAKEUP_CHARS). A console write
//! goes out synchronously under the same lock, so console messages and
//! a tty write's bytes never interleave (serial8250_console_write,
//! pl011_console_write).
//!
//! ## Locking
//!
//! `UartPort.xmit` is the port lock (Linux uart_port.lock), an
//! `IrqSpinlock` leaf: tty writes, the TX interrupt or poll timer, and
//! console writes (under `OUTPUT_LOCK`; only tried during an oops).
//! Writers are woken after it is released: a wakeup takes run-queue
//! locks, and printk (so the console write) may run under one.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::IrqSpinlock;
use crate::sync::spin::Mutex;

use super::TtyPort;
use crate::util::error::KernelError;
use crate::util::kfifo::Kfifo;

/// The transmit buffer's size (Linux UART_XMIT_SIZE, PAGE_SIZE)
pub const UART_XMIT_SIZE: usize = 4096;
/// Writers are woken when fewer bytes than this are queued (Linux
/// WAKEUP_CHARS)
pub const WAKEUP_CHARS: usize = 256;

/// struct serial_struct (Linux uapi/linux/serial.h), TIOCGSERIAL and
/// TIOCSSERIAL
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SerialStruct {
    pub type_: i32,
    pub line: i32,
    pub port: u32,
    pub irq: i32,
    pub flags: i32,
    pub xmit_fifo_size: i32,
    pub custom_divisor: i32,
    pub baud_base: i32,
    /// Centiseconds
    pub close_delay: u16,
    pub io_type: u8,
    pub reserved_char: u8,
    pub hub6: i32,
    /// Centiseconds; ASYNC_CLOSING_WAIT_INF or _NONE
    pub closing_wait: u16,
    pub closing_wait2: u16,
    _pad0: u32,
    pub iomem_base: u64,
    pub iomem_reg_shift: u16,
    _pad1: u16,
    pub port_high: u32,
    pub iomap_base: u64,
}
crate::pod!(SerialStruct {
    type_,
    line,
    port,
    irq,
    flags,
    xmit_fifo_size,
    custom_divisor,
    baud_base,
    close_delay,
    io_type,
    reserved_char,
    hub6,
    closing_wait,
    closing_wait2,
    _pad0,
    iomem_base,
    iomem_reg_shift,
    _pad1,
    port_high,
    iomap_base,
});

/// closing_wait: wait for output as long as it takes, or not at all
/// (Linux uapi/linux/serial.h)
pub const ASYNC_CLOSING_WAIT_INF: u16 = 0;
pub const ASYNC_CLOSING_WAIT_NONE: u16 = 65535;

/// Port types (Linux uapi/linux/serial.h, serial_core.h)
pub const PORT_UNKNOWN: i32 = 0;
pub const PORT_16550A: i32 = 4;
pub const PORT_CIRRUS: i32 = 5;
pub const PORT_STARTECH: i32 = 9;
pub const PORT_AMBA: i32 = 32;

/// I/O types (Linux uart_port.iotype)
pub const UPIO_PORT: u8 = 0;
pub const UPIO_MEM: u8 = 2;

/// Port flags (Linux UPF_*, the ASYNC_* bits user space sees)
pub const UPF_SKIP_TEST: u32 = 1 << 6;
pub const UPF_SPD_MASK: u32 = 0x1030;
pub const UPF_LOW_LATENCY: u32 = 1 << 13;
pub const UPF_BOOT_AUTOCONF: u32 = 1 << 28;
pub const UPF_FIXED_PORT: u32 = 1 << 29;
/// What TIOCSSERIAL changes with CAP_SYS_ADMIN, and without
const UPF_CHANGE_MASK: u32 = 0x17fff;
const UPF_USR_MASK: u32 = UPF_SPD_MASK | UPF_LOW_LATENCY;

/// A port's fixed resources (Linux uart_port: line, mapbase, iotype,
/// regshift; hub6 is 0)
pub struct UartDesc {
    pub line: i32,
    pub mapbase: u64,
    pub iotype: u8,
    pub regshift: u16,
}

/// What TIOCSSERIAL may change (Linux uart_port: type, iobase, irq,
/// flags, uartclk, custom_divisor, fifosize)
#[derive(Clone, Copy)]
pub struct UartCfg {
    pub type_: i32,
    /// I/O port base: TIOCSSERIAL's port and port_high << 32 (Linux
    /// HIGH_BITS_OFFSET on 64-bit)
    pub iobase: u64,
    pub irq: i32,
    pub flags: u32,
    pub uartclk: u32,
    pub custom_divisor: i32,
    pub fifosize: i32,
}

/// The flow control character a UART sends to throttle (`stop`) or
/// unthrottle its sender: STOP or START under IXOFF (Linux
/// uart_throttle, uart_unthrottle: UPSTAT_AUTOXOFF not done by the
/// hardware, so by uart_send_xchar)
pub fn ixoff_char(tty: &super::Tty, stop: bool) -> Option<u8> {
    use super::termios::{IXOFF, VSTART, VSTOP};
    let t = tty.get_termios();
    (t.c_iflag & IXOFF != 0).then(|| t.c_cc[if stop { VSTOP } else { VSTART }])
}

/// The highest interrupt number + 1 (Linux irq_get_nr_irqs)
fn nr_irqs() -> i64 {
    use crate::arch::{CurrentArch, IrqChipOps};
    i64::from(<CurrentArch as IrqChipOps>::FIRST_IRQ) + <CurrentArch as IrqChipOps>::NR_IRQS as i64
}

/// Centiseconds as ticks (Linux msecs_to_jiffies(cs * 10))
fn cs_to_ticks(cs: u16) -> u32 {
    crate::task::percpu::ms_to_ticks(u64::from(cs) * 10) as u32
}

/// Ticks as centiseconds (Linux jiffies_to_msecs(j) / 10)
fn ticks_to_cs(t: u32) -> u16 {
    (u64::from(t) * crate::task::percpu::TICK_MS / 10).min(u64::from(u16::MAX)) as u16
}

/// A UART's transmitter (Linux uart_ops, the transmit side), called
/// under the port lock
pub trait UartOps: Sync {
    /// Bytes the transmitter takes in one round now, from its interrupt
    /// or not (8250: its FIFO once THR is empty, else 0; PL011: half
    /// its FIFO from the interrupt, else until full, as pl011_tx_chars'
    /// from_irq)
    fn tx_burst(&self, from_irq: bool) -> usize;

    /// The transmit FIFO is full (PL011 FR.TXFF; 8250: never within a
    /// burst)
    fn tx_full(&self) -> bool {
        false
    }

    /// Put one byte in the transmitter
    fn tx_put(&self, b: u8);

    /// A round that sends the x_char sends nothing else (8250
    /// serial8250_tx_chars returns after uart_xchar_out; PL011 goes on)
    fn xchar_ends_round(&self) -> bool {
        false
    }

    /// Turn the TX interrupt on or off (8250 IER.THRI, PL011 IMSC.TXIM)
    fn tx_irq(&self, on: bool);

    /// Polled console output (Linux serial8250_console_putchar): wait
    /// for room, then write `b`
    fn console_putc(&self, b: u8);

    /// Wait until the transmitter is empty
    fn tx_drain(&self);

    /// Before a console write: quiet the port's interrupts, returning
    /// what `console_end` restores (Linux serial8250_console_write
    /// saves and clears IER)
    fn console_begin(&self) -> u32 {
        0
    }

    /// After a console write: restore what `console_begin` returned
    fn console_end(&self, saved: u32) {
        let _ = saved;
    }

    /// Arm the port's poll timer for the next tick (a port without an
    /// interrupt; its callback calls `UartPort::poll_tx`)
    fn arm_poll(&self);

    /// Check TIOCSSERIAL's settings for the port (Linux
    /// uart_ops.verify_port)
    fn verify_port(&self, ss: &SerialStruct) -> Result<(), KernelError> {
        let _ = ss;
        Ok(())
    }

    /// Bring the port up for use (Linux uart_ops.startup), without the
    /// port lock: an error if no UART answers there
    fn startup(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Take the port down (Linux uart_ops.shutdown), without the port
    /// lock
    fn shutdown(&self) {}

    /// Claim the port's registers (Linux uart_ops.request_port): EBUSY
    /// if someone else has them
    fn request_port(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Give the port's registers back (Linux uart_ops.release_port)
    fn release_port(&self) {}

    /// Drive the port at `iobase` as `type_` from now on (Linux sets
    /// uport->iobase and uport->type in uart_set_info)
    fn set_port(&self, iobase: u64, type_: i32) {
        let _ = (iobase, type_);
    }
}

/// The port lock's data (Linux uart_state.port.xmit_fifo)
struct Xmit {
    fifo: Kfifo<UART_XMIT_SIZE>,
    /// The TX interrupt (or the poll timer) is on
    tx_on: bool,
    /// Output is stopped (Linux tty->flow.stopped as uart_tx_stopped
    /// reads it; set by uart_stop, cleared by uart_start)
    stopped: bool,
    /// A flow control character to send ahead of the queue, 0 if none
    /// (Linux uart_port.x_char)
    x_char: u8,
    /// The transmit buffer exists: from the port's startup to its
    /// shutdown (Linux uart_alloc_xmit_buf, uart_shutdown's free); a
    /// write to a port without one takes nothing (uart_write)
    buf: bool,
}

/// A UART port: its lock and transmit buffer
pub struct UartPort {
    xmit: IrqSpinlock<Xmit>,
    /// It takes interrupts; else a timer polls the transmitter
    irq: AtomicBool,
    /// Its device is gone (Linux state->uart_port NULL after
    /// serial_core_remove_one_port): set and cleared under the tty's
    /// `port`
    detached: AtomicBool,
    desc: UartDesc,
    /// Spin leaf, thread context: under the tty's `port` mutex (Linux
    /// port->mutex) for TIOCSSERIAL, alone for probe
    cfg: Mutex<UartCfg>,
}

impl UartPort {
    pub const fn new(desc: UartDesc, cfg: UartCfg) -> Self {
        Self {
            desc,
            cfg: Mutex::new(cfg),
            xmit: IrqSpinlock::new(Xmit {
                fifo: Kfifo::new(),
                tx_on: false,
                stopped: false,
                x_char: 0,
                buf: false,
            }),
            irq: AtomicBool::new(false),
            detached: AtomicBool::new(false),
        }
    }

    /// The port's device goes (true) or comes (false) (Linux
    /// serial_core_remove_one_port, serial_core_add_one_port)
    pub fn detach(&self, gone: bool) {
        self.detached.store(gone, Ordering::Release);
    }

    /// The port's device is gone (Linux uart_port_check NULL)
    fn gone(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }

    /// Run `f` under the port lock (the driver's interrupt enables)
    pub fn locked<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.xmit.lock();
        f()
    }

    /// The port has an interrupt (probe) or lost it (remove); queued
    /// bytes move on with the new mode
    pub fn set_irq(&self, ops: &dyn UartOps, on: bool) -> bool {
        let mut x = self.xmit.lock();
        if x.tx_on {
            if self.irq.load(Ordering::Relaxed) {
                ops.tx_irq(false);
            }
            x.tx_on = false;
        }
        self.irq.store(on, Ordering::Relaxed);
        self.start_tx(ops, &mut x)
    }

    /// Turn the transmitter's interrupt (or poll timer) off (Linux
    /// stop_tx)
    fn stop_tx(&self, ops: &dyn UartOps, x: &mut Xmit) {
        if x.tx_on {
            if self.irq.load(Ordering::Relaxed) {
                ops.tx_irq(false);
            }
            x.tx_on = false;
        }
    }

    /// Send what the transmitter takes now: the x_char first, then the
    /// queue unless stopped; once nothing is left to send its interrupt
    /// goes off. True if writers should be woken (Linux
    /// serial8250_tx_chars, pl011_tx_chars: uart_write_wakeup below
    /// WAKEUP_CHARS)
    fn tx_chars(&self, ops: &dyn UartOps, x: &mut Xmit, from_irq: bool) -> bool {
        let mut n = ops.tx_burst(from_irq);
        if x.x_char != 0 {
            if n == 0 || ops.tx_full() {
                return false;
            }
            ops.tx_put(x.x_char);
            x.x_char = 0;
            n -= 1;
            if ops.xchar_ends_round() {
                return false;
            }
        }
        if x.stopped || x.fifo.is_empty() {
            self.stop_tx(ops, x);
            return false;
        }
        for _ in 0..n {
            if ops.tx_full() {
                break;
            }
            let mut b = [0u8];
            if x.fifo.pop(&mut b) == 0 {
                break;
            }
            ops.tx_put(b[0]);
        }
        let wake = x.fifo.len() < WAKEUP_CHARS;
        if x.fifo.is_empty() {
            self.stop_tx(ops, x);
        }
        wake
    }

    /// Start the transmitter (Linux ops->start_tx): what it takes now,
    /// then its interrupt or the poll timer for the rest. True if
    /// writers should be woken
    fn start_tx(&self, ops: &dyn UartOps, x: &mut Xmit) -> bool {
        if x.x_char == 0 && x.fifo.is_empty() {
            return false;
        }
        let wake = self.tx_chars(ops, x, false);
        let more = x.x_char != 0 || (!x.stopped && !x.fifo.is_empty());
        if more && !x.tx_on {
            x.tx_on = true;
            if self.irq.load(Ordering::Relaxed) {
                ops.tx_irq(true);
            } else {
                ops.arm_poll();
            }
        }
        wake
    }

    /// Start the transmitter unless output is stopped (Linux
    /// __uart_start)
    fn uart_start(&self, ops: &dyn UartOps, x: &mut Xmit) -> bool {
        !x.stopped && self.start_tx(ops, x)
    }

    /// A tty write (Linux uart_write): queue what fits, start the
    /// transmitter unless stopped; the bytes queued, and whether
    /// writers should be woken (after the port lock is released)
    pub fn write(&self, ops: &dyn UartOps, data: &[u8]) -> (usize, bool) {
        let mut x = self.xmit.lock();
        if !x.buf {
            return (0, false);
        }
        let n = x.fifo.push(data);
        let wake = self.uart_start(ops, &mut x);
        (n, wake)
    }

    /// Stop output (Linux uart_stop -> ops->stop_tx); queued bytes stay
    pub fn stop(&self, ops: &dyn UartOps) {
        let mut x = self.xmit.lock();
        x.stopped = true;
        self.stop_tx(ops, &mut x);
    }

    /// Restart output (Linux uart_start): true if writers should be
    /// woken
    pub fn start(&self, ops: &dyn UartOps) -> bool {
        let mut x = self.xmit.lock();
        x.stopped = false;
        self.uart_start(ops, &mut x)
    }

    /// Send `ch` ahead of the queue, stopped or not (Linux
    /// uart_send_xchar): true if writers should be woken
    pub fn send_xchar(&self, ops: &dyn UartOps, ch: u8) -> bool {
        let mut x = self.xmit.lock();
        x.x_char = ch;
        ch != 0 && self.start_tx(ops, &mut x)
    }

    /// The TX interrupt (Linux serial8250_handle_irq's THRE case,
    /// pl011_int's TX case): true if writers should be woken
    pub fn interrupt_tx(&self, ops: &dyn UartOps) -> bool {
        let mut x = self.xmit.lock();
        if !x.tx_on {
            return false;
        }
        self.tx_chars(ops, &mut x, true)
    }

    /// The poll timer of a port without an interrupt (Linux
    /// serial8250_timeout): true if writers should be woken
    pub fn poll_tx(&self, ops: &dyn UartOps) -> bool {
        let mut x = self.xmit.lock();
        if !x.tx_on || self.irq.load(Ordering::Relaxed) {
            return false;
        }
        let wake = self.tx_chars(ops, &mut x, true);
        if x.tx_on {
            ops.arm_poll();
        }
        wake
    }

    /// Room in the transmit buffer (Linux uart_write_room)
    pub fn write_room(&self) -> usize {
        let x = self.xmit.lock();
        if x.buf {
            UART_XMIT_SIZE - x.fifo.len()
        } else {
            0
        }
    }

    /// Bytes queued (Linux uart_chars_in_buffer)
    pub fn chars_in_buffer(&self) -> usize {
        self.xmit.lock().fifo.len()
    }

    /// Drop the queued bytes (Linux uart_flush_buffer)
    pub fn flush_buffer(&self) {
        self.xmit.lock().fifo.reset();
    }

    /// The tty's last close (Linux tty_port_shutdown): the tty's
    /// stopped state goes with it; `down`, the port is up and not a
    /// console, so it goes down (uart_tty_port_shutdown)
    pub fn shutdown(&self, ops: &dyn UartOps, down: bool) {
        self.xmit.lock().stopped = false;
        if down {
            self.down(ops, true);
        }
    }

    /// Bring the port up (Linux uart_port_startup): its transmit buffer,
    /// then the driver's startup. True if up; false if not but the
    /// caller may go on (Linux returns 1: an unknown port type, or a
    /// failed startup for CAP_SYS_ADMIN, so setserial can reconfigure
    /// it); else the driver's error
    pub fn port_startup(&self, ops: &dyn UartOps, admin: bool) -> Result<bool, KernelError> {
        if self.cfg.lock().type_ == PORT_UNKNOWN {
            return Ok(false);
        }
        self.xmit.lock().buf = true;
        match ops.startup() {
            Ok(()) => Ok(true),
            Err(_) if admin => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Linux uart_shutdown's port part (a hangup's, a removal's): if
    /// `up`, the transmitter stopped and the port taken down
    /// (uart_port_shutdown, which takes the port lock itself); then the
    /// transmit buffer freed, queued output and the x_char with it
    /// (uart_free_xmit_buf); the tty's stopped state stays with the tty
    pub fn down(&self, ops: &dyn UartOps, up: bool) {
        if up {
            self.stop_tx(ops, &mut self.xmit.lock());
            ops.shutdown();
        }
        let mut x = self.xmit.lock();
        x.fifo.reset();
        x.x_char = 0;
        x.buf = false;
    }

    /// The port's interrupt number (probe)
    pub fn set_irq_nr(&self, irq: i32) {
        self.cfg.lock().irq = irq;
    }

    /// The port's interrupt number, 0 if none (Linux uport->irq)
    pub fn irq_nr(&self) -> i32 {
        self.cfg.lock().irq
    }

    /// TIOCGSERIAL (Linux uart_get_info), under the tty's `port`:
    /// ENODEV once the port's device is gone
    pub fn get_info(&self, port: &TtyPort) -> Result<SerialStruct, KernelError> {
        if self.gone() {
            return Err(KernelError::NoDevice);
        }
        let c = *self.cfg.lock();
        let d = &self.desc;
        Ok(SerialStruct {
            type_: c.type_,
            line: d.line,
            port: c.iobase as u32,
            port_high: (c.iobase >> 32) as u32,
            irq: c.irq,
            flags: c.flags as i32,
            xmit_fifo_size: c.fifosize,
            baud_base: (c.uartclk / 16) as i32,
            close_delay: ticks_to_cs(port.close_delay),
            closing_wait: if port.closing_wait == u32::from(ASYNC_CLOSING_WAIT_NONE) {
                ASYNC_CLOSING_WAIT_NONE
            } else {
                ticks_to_cs(port.closing_wait)
            },
            custom_divisor: c.custom_divisor,
            io_type: d.iotype,
            iomem_reg_shift: d.regshift,
            iomem_base: d.mapbase,
            ..SerialStruct::default()
        })
    }

    /// TIOCSSERIAL (Linux uart_set_info), under the tty's `port`:
    /// `users`, the port's opens (0: hung up, not active); `admin`, the
    /// caller has CAP_SYS_ADMIN, else only the user flags (speed, low
    /// latency) and the custom divisor change. A move to another I/O
    /// address, type or interrupt takes the port down, releases its
    /// registers and claims the new ones (EBUSY, the old ones back, if
    /// they are taken), then brings it up again where it can (a port
    /// that does not start stays down, the tty's I/O failing with EIO
    /// until a new open: Linux TTY_IO_ERROR)
    pub fn set_info(
        &self,
        ops: &dyn UartOps,
        tty: &super::Tty,
        port: &mut TtyPort,
        ss: &SerialStruct,
        users: usize,
        admin: bool,
    ) -> Result<(), KernelError> {
        // A port whose device is gone, or one hung up (Linux: !uport,
        // !tty_port_active)
        if self.gone() || users == 0 {
            return Err(KernelError::Io);
        }
        let new_port = u64::from(ss.port) | u64::from(ss.port_high) << 32;
        let mut ss = *ss;
        ss.irq = crate::arch::irq_canonicalize(ss.irq);
        let ss = &ss;
        let mut c = self.cfg.lock();
        let d = &self.desc;
        let close_delay = cs_to_ticks(ss.close_delay);
        let closing_wait = if ss.closing_wait == ASYNC_CLOSING_WAIT_NONE {
            u32::from(ASYNC_CLOSING_WAIT_NONE)
        } else {
            cs_to_ticks(ss.closing_wait)
        };
        let fixed = c.flags & UPF_FIXED_PORT != 0;
        let change_irq = !fixed && ss.irq != c.irq;
        let change_port = !fixed && (new_port != c.iobase || ss.type_ != c.type_);
        // Another I/O type or a memory-mapped address: the port's
        // registers would be iomem, which has no resource tree here
        // (BUGS.md "Resource tree gaps")
        let change_io = !fixed
            && (ss.iomem_base != d.mapbase
                || ss.hub6 != 0
                || ss.io_type != d.iotype
                || ss.iomem_reg_shift != d.regshift);
        let new_flags = ss.flags as u32;
        if !fixed && ss.baud_base.wrapping_mul(16) == 0 {
            return Err(KernelError::InvalidArgument);
        }
        if !admin {
            if change_irq
                || change_port
                || change_io
                || ss.baud_base as u32 != c.uartclk / 16
                || close_delay != port.close_delay
                || closing_wait != port.closing_wait
                || (ss.xmit_fifo_size != 0 && ss.xmit_fifo_size != c.fifosize)
                || (new_flags ^ c.flags) & !UPF_USR_MASK != 0
            {
                return Err(KernelError::NotPermitted);
            }
            c.flags = (c.flags & !UPF_USR_MASK) | (new_flags & UPF_USR_MASK);
            c.custom_divisor = ss.custom_divisor;
            drop(c);
            return self.check_and_exit(ops, tty, port, admin);
        }
        ops.verify_port(ss)?;
        if i64::from(ss.irq) >= nr_irqs() || ss.irq < 0 || ss.baud_base < 9600 {
            return Err(KernelError::InvalidArgument);
        }
        if change_io {
            return Err(KernelError::InvalidArgument);
        }
        if change_port || change_irq {
            // Only its sole user may move it
            if users > 1 {
                return Err(KernelError::Busy);
            }
            drop(c);
            self.shutdown_tty(ops, tty, port);
            c = self.cfg.lock();
        }
        if change_port {
            drop(c);
            self.change_port(ops, new_port, ss.type_)?;
            c = self.cfg.lock();
        }
        if change_irq {
            c.irq = ss.irq;
        }
        if !fixed {
            c.uartclk = (ss.baud_base as u32).wrapping_mul(16);
        }
        c.flags = (c.flags & !UPF_CHANGE_MASK) | (new_flags & UPF_CHANGE_MASK);
        c.custom_divisor = ss.custom_divisor;
        port.close_delay = close_delay;
        port.closing_wait = closing_wait;
        if ss.xmit_fifo_size != 0 {
            c.fifosize = ss.xmit_fifo_size;
        }
        drop(c);
        self.check_and_exit(ops, tty, port, admin)
    }

    /// The end of TIOCSSERIAL (Linux uart_set_info's check_and_exit): a
    /// port that is down comes up again (uart_startup with init_hw);
    /// the tty's I/O error stays until a new open finds the port down
    /// or the tty is closed (tty_port_open, release_tty)
    fn check_and_exit(
        &self,
        ops: &dyn UartOps,
        tty: &super::Tty,
        port: &mut TtyPort,
        admin: bool,
    ) -> Result<(), KernelError> {
        if self.cfg.lock().type_ != PORT_UNKNOWN && !port.initialized {
            match self.port_startup(ops, admin) {
                Ok(true) => port.initialized = true,
                // Linux uart_startup: TTY_IO_ERROR; 1 is success here
                Ok(false) => tty.set_io_error(true),
                Err(e) => {
                    tty.set_io_error(true);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Move the port to `iobase` as `type_` (Linux uart_change_port):
    /// its registers released, the new ones claimed; if they are taken,
    /// the old settings come back with their registers (EBUSY; the
    /// port's type unknown if those are gone too). Under the tty's
    /// `port`, not `cfg`: claiming allocates
    fn change_port(&self, ops: &dyn UartOps, iobase: u64, type_: i32) -> Result<(), KernelError> {
        let (old_iobase, old_type) = {
            let c = self.cfg.lock();
            (c.iobase, c.type_)
        };
        if old_type != PORT_UNKNOWN {
            ops.release_port();
        }
        self.set_port(ops, iobase, type_);
        if type_ == PORT_UNKNOWN {
            return Ok(());
        }
        let Err(e) = ops.request_port() else {
            return Ok(());
        };
        self.set_port(ops, old_iobase, old_type);
        if old_type == PORT_UNKNOWN {
            return Err(e);
        }
        if ops.request_port().is_err() {
            self.set_port(ops, old_iobase, PORT_UNKNOWN);
        }
        Err(KernelError::Busy)
    }

    /// Record the port's address and type, for TIOCGSERIAL and the
    /// driver
    fn set_port(&self, ops: &dyn UartOps, iobase: u64, type_: i32) {
        {
            let mut c = self.cfg.lock();
            c.iobase = iobase;
            c.type_ = type_;
        }
        ops.set_port(iobase, type_);
    }

    /// The port's I/O address and type
    pub fn port(&self) -> (u64, i32) {
        let c = self.cfg.lock();
        (c.iobase, c.type_)
    }

    /// Take a tty's port down (Linux uart_shutdown with a tty): its I/O
    /// fails from now on (TTY_IO_ERROR), the port down if it was up
    fn shutdown_tty(&self, ops: &dyn UartOps, tty: &super::Tty, port: &mut TtyPort) {
        tty.set_io_error(true);
        let up = core::mem::replace(&mut port.initialized, false);
        self.down(ops, up);
    }

    /// Linux uart_port_activate: ENXIO once the port's device is gone,
    /// else uart_startup without init_hw
    pub fn activate(&self, ops: &dyn UartOps, admin: bool) -> Result<bool, KernelError> {
        if self.gone() {
            return Err(KernelError::NoDeviceOrAddress);
        }
        self.port_startup(ops, admin)
    }

    /// A console write: under the port lock, only tried during an oops
    /// (output then goes out unlocked, as Linux's `locked = 0`), the
    /// port's interrupts quiet, each LF preceded by CR (Linux
    /// uart_console_write), then the transmitter drained
    pub fn console_write(&self, ops: &dyn UartOps, data: &[u8]) {
        let _g = if crate::printk::oops_in_progress() {
            self.xmit.try_lock()
        } else {
            Some(self.xmit.lock())
        };
        let saved = ops.console_begin();
        for &b in data {
            if b == b'\n' {
                ops.console_putc(b'\r');
            }
            ops.console_putc(b);
        }
        ops.tx_drain();
        ops.console_end(saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    /// A UART whose transmitter takes 4 bytes a round; its registers
    /// can be claimed at `taken` only by someone else, and a startup
    /// fails at `absent` (no UART there)
    struct Fake {
        out: Mutex<Vec<u8>>,
        irq_on: AtomicBool,
        rounds: AtomicUsize,
        at: core::sync::atomic::AtomicU64,
        claimed: Mutex<Vec<u64>>,
    }

    const TAKEN: u64 = 0x3f8;
    const ABSENT: u64 = 0x3e8;

    fn fake() -> Fake {
        Fake {
            out: Mutex::new(Vec::new()),
            irq_on: AtomicBool::new(false),
            rounds: AtomicUsize::new(0),
            at: core::sync::atomic::AtomicU64::new(0x2f8),
            claimed: Mutex::new(alloc::vec![0x2f8]),
        }
    }

    /// The tty TIOCSSERIAL marks (TTY_IO_ERROR)
    struct NullTty;

    impl super::super::TtyDriver for NullTty {
        fn write(&self, _tty: &super::super::Tty, data: &[u8]) -> Result<usize, KernelError> {
            Ok(data.len())
        }
        fn send_xchar(&self, _tty: &super::super::Tty, _ch: u8) {}
        fn console_write(&self, _data: &[u8]) {}
    }

    static NULL_TTY: NullTty = NullTty;

    /// A driver counting its hangups' `up` (taken down) calls
    struct DownTty(AtomicUsize);

    impl super::super::TtyDriver for DownTty {
        fn write(&self, _tty: &super::super::Tty, data: &[u8]) -> Result<usize, KernelError> {
            Ok(data.len())
        }
        fn send_xchar(&self, _tty: &super::super::Tty, _ch: u8) {}
        fn console_write(&self, _data: &[u8]) {}
        fn hangup(&self, up: bool) {
            if up {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    static DOWN_TTY: DownTty = DownTty(AtomicUsize::new(0));
    static REMOVED: super::super::Tty = super::super::Tty::new(
        "r",
        crate::fs::chardev::DevId::new(crate::fs::chardev::major::TTYS, 98),
        &DOWN_TTY,
    );

    /// A removed port still up (Linux serial_core_remove_one_port:
    /// uart_shutdown(NULL)) goes down once, the tty's I/O error unset
    #[test]
    fn port_remove_takes_down() {
        REMOVED.port.lock().initialized = true;
        REMOVED.port_remove();
        assert!(!REMOVED.port.lock().initialized);
        assert_eq!(DOWN_TTY.0.load(Ordering::Relaxed), 1);
        assert!(!REMOVED.io_error());
        REMOVED.port_remove();
        assert_eq!(DOWN_TTY.0.load(Ordering::Relaxed), 1);
    }
    static TTY: super::super::Tty = super::super::Tty::new(
        "t",
        crate::fs::chardev::DevId::new(crate::fs::chardev::major::TTYS, 99),
        &NULL_TTY,
    );

    impl UartOps for Fake {
        fn tx_burst(&self, _from_irq: bool) -> usize {
            self.rounds.fetch_add(1, Ordering::Relaxed);
            4
        }
        fn tx_put(&self, b: u8) {
            self.out.lock().unwrap().push(b);
        }
        fn tx_irq(&self, on: bool) {
            self.irq_on.store(on, Ordering::Relaxed);
        }
        fn console_putc(&self, b: u8) {
            self.out.lock().unwrap().push(b);
        }
        fn tx_drain(&self) {}
        fn arm_poll(&self) {}
        fn startup(&self) -> Result<(), KernelError> {
            if self.at.load(Ordering::Relaxed) == ABSENT {
                return Err(KernelError::NoDevice);
            }
            Ok(())
        }
        fn request_port(&self) -> Result<(), KernelError> {
            let at = self.at.load(Ordering::Relaxed);
            let mut c = self.claimed.lock().unwrap();
            // Linux __request_region: outside the root or busy
            if at > 0xffff || at == TAKEN || c.contains(&at) {
                return Err(KernelError::Busy);
            }
            c.push(at);
            Ok(())
        }
        fn release_port(&self) {
            let at = self.at.load(Ordering::Relaxed);
            self.claimed.lock().unwrap().retain(|&x| x != at);
        }
        fn set_port(&self, iobase: u64, _type: i32) {
            self.at.store(iobase, Ordering::Relaxed);
        }
    }

    const fn port() -> UartPort {
        UartPort::new(
            UartDesc {
                line: 0,
                mapbase: 0,
                iotype: UPIO_PORT,
                regshift: 0,
            },
            UartCfg {
                type_: PORT_16550A,
                iobase: 0x2f8,
                irq: 4,
                flags: UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
                uartclk: 1_843_200,
                custom_divisor: 0,
                fifosize: 16,
            },
        )
    }

    static PORT: UartPort = port();

    /// A write queues and sends a burst, the TX interrupt the rest; the
    /// interrupt goes off once empty; a console write in between goes
    /// out whole
    #[test]
    fn xmit_drains_by_interrupt() {
        let f = fake();
        PORT.irq.store(true, Ordering::Relaxed);
        // Down: no transmit buffer, nothing taken (Linux uart_write)
        assert_eq!(PORT.write(&f, b"abcdefghij"), (0, false));
        assert_eq!(PORT.write_room(), 0);
        assert_eq!(PORT.activate(&f, false), Ok(true));
        assert_eq!(PORT.write(&f, b"abcdefghij"), (10, true));
        assert_eq!(&*f.out.lock().unwrap(), b"abcd");
        assert!(f.irq_on.load(Ordering::Relaxed));
        assert_eq!(PORT.chars_in_buffer(), 6);
        PORT.console_write(&f, b"K\n");
        assert!(PORT.interrupt_tx(&f));
        assert!(PORT.interrupt_tx(&f));
        assert!(!f.irq_on.load(Ordering::Relaxed));
        assert_eq!(&*f.out.lock().unwrap(), b"abcdK\r\nefghij");
        assert_eq!(PORT.write_room(), UART_XMIT_SIZE);
        // Full: a write takes what fits
        let big = [b'x'; UART_XMIT_SIZE + 100];
        let (n, wake) = PORT.write(&f, &big);
        assert_eq!((n, wake), (UART_XMIT_SIZE, false));
        PORT.flush_buffer();
        assert_eq!(PORT.chars_in_buffer(), 0);
    }

    static STOP_PORT: UartPort = port();

    /// Stopped, a write only queues; an x_char still goes out; a
    /// restart sends the queue
    #[test]
    fn xmit_stop_start() {
        let f = fake();
        STOP_PORT.irq.store(true, Ordering::Relaxed);
        assert_eq!(STOP_PORT.activate(&f, false), Ok(true));
        STOP_PORT.stop(&f);
        assert_eq!(STOP_PORT.write(&f, b"abcdef"), (6, false));
        assert!(f.out.lock().unwrap().is_empty());
        assert!(!f.irq_on.load(Ordering::Relaxed));
        assert!(!STOP_PORT.send_xchar(&f, 0x13));
        assert_eq!(&*f.out.lock().unwrap(), b"\x13");
        assert!(!f.irq_on.load(Ordering::Relaxed));
        assert_eq!(STOP_PORT.chars_in_buffer(), 6);
        assert!(STOP_PORT.start(&f));
        assert_eq!(&*f.out.lock().unwrap(), b"\x13abcd");
        assert!(f.irq_on.load(Ordering::Relaxed));
        assert!(STOP_PORT.interrupt_tx(&f));
        assert_eq!(&*f.out.lock().unwrap(), b"\x13abcdef");
        assert!(!f.irq_on.load(Ordering::Relaxed));
    }

    /// TIOCGSERIAL shows the port and tty_port defaults; TIOCSSERIAL
    /// without CAP_SYS_ADMIN changes only the user flags and the custom
    /// divisor (Linux uart_set_info); with it the close timing too,
    /// within verify_port and the generic checks
    #[test]
    fn serial_info_rules() {
        let f = fake();
        let p = port();
        let mut tp = TtyPort {
            initialized: true,
            close_delay: 50,
            closing_wait: 3000,
        };
        let ss = p.get_info(&tp).unwrap();
        assert_eq!(
            (ss.type_, ss.port, ss.irq, ss.baud_base, ss.xmit_fifo_size),
            (PORT_16550A, 0x2f8, 4, 115_200, 16)
        );
        assert_eq!((ss.close_delay, ss.closing_wait), (50, 3000));
        let set = |tp: &mut TtyPort, s: &SerialStruct, admin| p.set_info(&f, &TTY, tp, s, 1, admin);
        let mut s2 = ss;
        s2.closing_wait = 100;
        assert_eq!(set(&mut tp, &s2, false), Err(KernelError::NotPermitted));
        let mut s3 = ss;
        s3.flags ^= UPF_SKIP_TEST as i32;
        assert_eq!(set(&mut tp, &s3, false), Err(KernelError::NotPermitted));
        let mut s4 = ss;
        s4.flags |= UPF_LOW_LATENCY as i32;
        s4.custom_divisor = 3;
        assert_eq!(set(&mut tp, &s4, false), Ok(()));
        let got = p.get_info(&tp).unwrap();
        assert_eq!((got.flags, got.custom_divisor), (s4.flags, 3));
        let mut s5 = got;
        s5.closing_wait = ASYNC_CLOSING_WAIT_NONE;
        s5.close_delay = 7;
        assert_eq!(set(&mut tp, &s5, true), Ok(()));
        assert_eq!(tp.closing_wait, u32::from(ASYNC_CLOSING_WAIT_NONE));
        let got = p.get_info(&tp).unwrap();
        assert_eq!(
            (got.close_delay, got.closing_wait),
            (7, ASYNC_CLOSING_WAIT_NONE)
        );
        let mut s6 = got;
        s6.baud_base = 0;
        assert_eq!(set(&mut tp, &s6, true), Err(KernelError::InvalidArgument));
        s6.baud_base = 4800;
        assert_eq!(set(&mut tp, &s6, true), Err(KernelError::InvalidArgument));
        let mut s7 = got;
        s7.irq = 3;
        assert_eq!(
            p.set_info(&f, &TTY, &mut tp, &s7, 2, true),
            Err(KernelError::Busy)
        );
        assert_eq!(
            p.set_info(&f, &TTY, &mut tp, &got, 0, true),
            Err(KernelError::Io)
        );
    }

    /// A port move (Linux uart_set_info, uart_change_port): to an
    /// address with no UART it succeeds for CAP_SYS_ADMIN, the port
    /// down and the tty's I/O failing; to taken registers EBUSY, the
    /// old ones claimed again; home, the port is up again, the I/O
    /// error left for a new open
    #[test]
    fn port_move() {
        let f = fake();
        let p = port();
        let mut tp = TtyPort::new();
        assert_eq!(p.activate(&f, true), Ok(true));
        tp.initialized = true;
        TTY.set_io_error(false);
        let home = p.get_info(&tp).unwrap();
        let mut ss = home;
        ss.port = ABSENT as u32;
        assert_eq!(p.set_info(&f, &TTY, &mut tp, &ss, 1, true), Ok(()));
        assert!(!tp.initialized && TTY.io_error());
        assert_eq!(p.port(), (ABSENT, PORT_16550A));
        assert_eq!(&*f.claimed.lock().unwrap(), &[ABSENT]);
        ss.port = TAKEN as u32;
        assert_eq!(
            p.set_info(&f, &TTY, &mut tp, &ss, 1, true),
            Err(KernelError::Busy)
        );
        assert_eq!(p.port(), (ABSENT, PORT_16550A));
        assert_eq!(&*f.claimed.lock().unwrap(), &[ABSENT]);
        assert_eq!(p.set_info(&f, &TTY, &mut tp, &home, 1, true), Ok(()));
        assert!(tp.initialized && TTY.io_error());
        assert_eq!(&*f.claimed.lock().unwrap(), &[0x2f8]);
        assert_eq!(p.write(&f, b"x"), (1, true));
        // Without CAP_SYS_ADMIN a port that does not start fails the
        // open (Linux uart_port_startup's capable check)
        f.at.store(ABSENT, Ordering::Relaxed);
        p.down(&f, true);
        assert_eq!(p.activate(&f, false), Err(KernelError::NoDevice));
        assert_eq!(p.activate(&f, true), Ok(false));
    }

    /// TIOCSSERIAL's port_high is the iobase's high half (Linux
    /// HIGH_BITS_OFFSET): an address above the I/O space cannot be
    /// claimed (EBUSY, the port stays); an IRQ is canonical (x86: 2 is
    /// 9)
    #[test]
    fn port_high_and_irq() {
        let f = fake();
        let p = port();
        let mut tp = TtyPort::new();
        assert_eq!(p.activate(&f, true), Ok(true));
        tp.initialized = true;
        let home = p.get_info(&tp).unwrap();
        let mut ss = home;
        ss.port_high = 1;
        assert_eq!(
            p.set_info(&f, &TTY, &mut tp, &ss, 1, true),
            Err(KernelError::Busy)
        );
        assert_eq!(p.port(), (0x2f8, PORT_16550A));
        let mut ss = home;
        ss.irq = 2;
        assert_eq!(p.set_info(&f, &TTY, &mut tp, &ss, 1, true), Ok(()));
        let want = if cfg!(target_arch = "x86_64") { 9 } else { 2 };
        assert_eq!(p.get_info(&tp).unwrap().irq, want);
    }

    /// A port whose device is gone (Linux uart_port_check NULL): an
    /// open ENXIO, TIOCSSERIAL EIO, TIOCGSERIAL ENODEV, until it comes
    /// back
    #[test]
    fn detached_port() {
        let f = fake();
        let p = port();
        let mut tp = TtyPort::new();
        let ss = p.get_info(&tp).unwrap();
        p.detach(true);
        assert_eq!(p.activate(&f, true), Err(KernelError::NoDeviceOrAddress));
        assert_eq!(
            p.set_info(&f, &TTY, &mut tp, &ss, 1, true),
            Err(KernelError::Io)
        );
        assert_eq!(p.get_info(&tp), Err(KernelError::NoDevice));
        p.detach(false);
        assert_eq!(p.activate(&f, true), Ok(true));
    }
}

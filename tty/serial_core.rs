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

/// A port's fixed resources (Linux uart_port: type, line, iobase,
/// mapbase, iotype, regshift; hub6 is 0)
pub struct UartDesc {
    pub type_: i32,
    pub line: i32,
    pub iobase: u32,
    pub mapbase: u64,
    pub iotype: u8,
    pub regshift: u16,
}

/// What TIOCSSERIAL may change (Linux uart_port: irq, flags, uartclk,
/// custom_divisor, fifosize)
#[derive(Clone, Copy)]
pub struct UartCfg {
    pub irq: i32,
    pub flags: u32,
    pub uartclk: u32,
    pub custom_divisor: i32,
    pub fifosize: i32,
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
}

/// A UART port: its lock and transmit buffer
pub struct UartPort {
    xmit: IrqSpinlock<Xmit>,
    /// It takes interrupts; else a timer polls the transmitter
    irq: AtomicBool,
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
            }),
            irq: AtomicBool::new(false),
        }
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
        UART_XMIT_SIZE - self.xmit.lock().fifo.len()
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
    /// stopped state goes with it; unless a console, the transmitter
    /// stops and the queue is freed (uart_shutdown,
    /// uart_free_xmit_buf)
    pub fn shutdown(&self, ops: &dyn UartOps, console: bool) {
        let mut x = self.xmit.lock();
        x.stopped = false;
        if !console {
            self.stop_tx(ops, &mut x);
            x.fifo.reset();
            x.x_char = 0;
        }
    }

    /// The port's interrupt number (probe)
    pub fn set_irq_nr(&self, irq: i32) {
        self.cfg.lock().irq = irq;
    }

    /// TIOCGSERIAL (Linux uart_get_info), under the tty's `port`
    pub fn get_info(&self, port: &TtyPort) -> SerialStruct {
        let c = *self.cfg.lock();
        let d = &self.desc;
        SerialStruct {
            type_: d.type_,
            line: d.line,
            port: d.iobase,
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
        }
    }

    /// TIOCSSERIAL (Linux uart_set_info), under the tty's `port`:
    /// `active`, the port is open and not hung up; `users`, its open
    /// files; `admin`, the caller has CAP_SYS_ADMIN, else only the
    /// user flags (speed, low latency) and the custom divisor change.
    /// hk cannot move a port to other resources: a change of its I/O
    /// address, type or interrupt that Linux would make is EINVAL
    pub fn set_info(
        &self,
        ops: &dyn UartOps,
        port: &mut TtyPort,
        ss: &SerialStruct,
        active: bool,
        users: usize,
        admin: bool,
    ) -> Result<(), KernelError> {
        if !active {
            return Err(KernelError::Io);
        }
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
        let change_port = !fixed
            && (ss.port != d.iobase
                || ss.iomem_base != d.mapbase
                || ss.hub6 != 0
                || ss.io_type != d.iotype
                || ss.iomem_reg_shift != d.regshift
                || ss.type_ != d.type_);
        let new_flags = ss.flags as u32;
        if !fixed && ss.baud_base.wrapping_mul(16) == 0 {
            return Err(KernelError::InvalidArgument);
        }
        if !admin {
            if change_irq
                || change_port
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
            return Ok(());
        }
        ops.verify_port(ss)?;
        if i64::from(ss.irq) >= nr_irqs() || ss.irq < 0 || ss.baud_base < 9600 {
            return Err(KernelError::InvalidArgument);
        }
        if change_port || change_irq {
            if users > 1 {
                return Err(KernelError::Busy);
            }
            return Err(KernelError::InvalidArgument);
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
        Ok(())
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

    /// A UART whose transmitter takes 4 bytes a round
    struct Fake {
        out: Mutex<Vec<u8>>,
        irq_on: AtomicBool,
        rounds: AtomicUsize,
    }

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
    }

    const fn port() -> UartPort {
        UartPort::new(
            UartDesc {
                type_: PORT_16550A,
                line: 0,
                iobase: 0x3f8,
                mapbase: 0,
                iotype: UPIO_PORT,
                regshift: 0,
            },
            UartCfg {
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
        let f = Fake {
            out: Mutex::new(Vec::new()),
            irq_on: AtomicBool::new(false),
            rounds: AtomicUsize::new(0),
        };
        PORT.irq.store(true, Ordering::Relaxed);
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
        let f = Fake {
            out: Mutex::new(Vec::new()),
            irq_on: AtomicBool::new(false),
            rounds: AtomicUsize::new(0),
        };
        STOP_PORT.irq.store(true, Ordering::Relaxed);
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
        let f = Fake {
            out: Mutex::new(Vec::new()),
            irq_on: AtomicBool::new(false),
            rounds: AtomicUsize::new(0),
        };
        let p = port();
        let mut tp = TtyPort {
            close_delay: 50,
            closing_wait: 3000,
        };
        let ss = p.get_info(&tp);
        assert_eq!(
            (ss.type_, ss.port, ss.irq, ss.baud_base, ss.xmit_fifo_size),
            (PORT_16550A, 0x3f8, 4, 115_200, 16)
        );
        assert_eq!((ss.close_delay, ss.closing_wait), (50, 3000));
        let set = |tp: &mut TtyPort, s: &SerialStruct, admin| p.set_info(&f, tp, s, true, 1, admin);
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
        let got = p.get_info(&tp);
        assert_eq!((got.flags, got.custom_divisor), (s4.flags, 3));
        let mut s5 = got;
        s5.closing_wait = ASYNC_CLOSING_WAIT_NONE;
        s5.close_delay = 7;
        assert_eq!(set(&mut tp, &s5, true), Ok(()));
        assert_eq!(tp.closing_wait, u32::from(ASYNC_CLOSING_WAIT_NONE));
        let got = p.get_info(&tp);
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
            p.set_info(&f, &mut tp, &s7, true, 2, true),
            Err(KernelError::Busy)
        );
        assert_eq!(
            p.set_info(&f, &mut tp, &got, false, 1, true),
            Err(KernelError::Io)
        );
    }
}

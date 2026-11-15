//! Serial TTY Driver
//!
//! NS16550A-compatible UART driver implementing TtyDriver.
//!
//! This provides the hardware interface for serial ports like /dev/ttyS0.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::console::{ConsolePriority, register_console};
use crate::irq::{IrqFn, IrqRegistration, IrqReturn};
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};

use crate::fs::chardev::{DevId, major};
use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

use crate::time::timer::{TIMER_HARD, TimerList};
use crate::tty::serial_core::{
    PORT_16550A, PORT_CIRRUS, PORT_STARTECH, PORT_UNKNOWN, UPF_BOOT_AUTOCONF, UPF_SKIP_TEST,
    UPIO_PORT, UartCfg, UartDesc, UartOps, UartPort,
};
use crate::tty::{Tty, TtyDriver};

/// NS16550A register offsets
mod regs {
    /// Transmit Holding Register (write) / Receive Buffer Register (read)
    pub const THR: u16 = 0;
    pub const RBR: u16 = 0;
    /// Interrupt Enable Register
    pub const IER: u16 = 1;
    /// Divisor Latch Low (when DLAB=1)
    pub const DLL: u16 = 0;
    /// Divisor Latch High (when DLAB=1)
    pub const DLH: u16 = 1;
    /// FIFO Control Register
    pub const FCR: u16 = 2;
    /// Interrupt Identification Register (read)
    pub const IIR: u16 = 2;
    /// Line Control Register
    pub const LCR: u16 = 3;
    /// Modem Control Register
    pub const MCR: u16 = 4;
    /// Line Status Register
    pub const LSR: u16 = 5;
}

/// Line Status Register bits
mod lsr {
    /// Data Ready
    pub const DR: u8 = 0x01;
    /// Transmitter Holding Register Empty
    pub const THRE: u8 = 0x20;
    /// Transmitter Empty (both THR and shift register empty)
    pub const TEMT: u8 = 0x40;
}

/// Interrupt Enable Register bits
mod ier {
    /// Received Data available Interrupt
    pub const RDI: u8 = 0x01;
    /// Transmitter Holding Register Empty Interrupt (Linux UART_IER_THRI)
    pub const THRI: u8 = 0x02;
}

/// Bytes the transmitter takes once THR is empty: the 16550A's FIFO
/// (Linux tx_loadsz)
const TX_LOADSZ: usize = 16;

/// Interrupt Identification Register bits
mod iir {
    /// No interrupt pending
    pub const NO_INT: u8 = 0x01;
}

/// Line Control Register bits
mod lcr {
    /// Divisor Latch Access Bit
    pub const DLAB: u8 = 0x80;
    /// 8 data bits, no parity, 1 stop bit
    pub const MODE_8N1: u8 = 0x03;
}

/// Modem Control Register bits
mod mcr {
    /// Data Terminal Ready
    pub const DTR: u8 = 0x01;
    /// Request To Send
    pub const RTS: u8 = 0x02;
    /// Auxiliary Output 2 (enables interrupts on PC)
    pub const OUT2: u8 = 0x08;
}

/// FIFO Control Register bits
mod fcr {
    /// Enable FIFO
    pub const ENABLE: u8 = 0x01;
    /// Clear receive FIFO
    pub const CLEAR_RX: u8 = 0x02;
    /// Clear transmit FIFO
    pub const CLEAR_TX: u8 = 0x04;
    /// 14-byte trigger level
    pub const TRIGGER_14: u8 = 0xC0;
}

/// Serial port (NS16550A UART) driver
///
/// tty output goes through the port's transmit buffer, drained by the
/// THRE interrupt (a timer without one); console output is polled.
/// COM1 input comes by interrupt (`rx_irq_init`).
pub struct SerialTty {
    /// I/O port base address (Linux uport->iobase, moved by
    /// TIOCSSERIAL)
    port: AtomicU16,
    /// Its port lock and transmit buffer (Linux uart_port)
    uart: UartPort,
    /// IER as last written (Linux up->ier), under the port lock
    ier: AtomicU8,
    /// Polls the transmitter while it has no interrupt (Linux up->timer)
    poll: &'static TimerList,
}

impl SerialTty {
    /// Create a new serial TTY
    ///
    /// ttyS`line` at I/O port `port` (e.g., 0x3F8 for COM1) on
    /// interrupt `irq` (Linux SERIAL_PORT_DFNS); `poll`: its
    /// transmitter poll timer
    pub const fn new(line: i32, port: u16, irq: i32, poll: &'static TimerList) -> Self {
        Self {
            port: AtomicU16::new(port),
            uart: UartPort::new(
                UartDesc {
                    line,
                    mapbase: 0,
                    iotype: UPIO_PORT,
                    regshift: 0,
                },
                // Linux STD_COMX_FLAGS, BASE_BAUD * 16, the 16550A's FIFO
                UartCfg {
                    type_: PORT_16550A,
                    iobase: port as u32,
                    irq,
                    flags: UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
                    uartclk: 1_843_200,
                    custom_divisor: 0,
                    fifosize: TX_LOADSZ as i32,
                },
            ),
            ier: AtomicU8::new(0),
            poll,
        }
    }

    /// Write IER (under the port lock)
    fn set_ier(&self, v: u8) {
        self.ier.store(v, Ordering::Relaxed);
        // SAFETY: IER is a register of this UART
        unsafe { self.outb(regs::IER, v) };
    }

    /// Initialize the UART hardware
    ///
    /// # Arguments
    /// * `baud_rate` - Desired baud rate (e.g., 115200)
    pub fn init_hardware(&self, baud_rate: u32) {
        // Calculate divisor: 115200 base clock / baud_rate
        let divisor = 115200 / baud_rate;

        unsafe {
            // Disable interrupts
            self.outb(regs::IER, 0x00);

            // Enable DLAB to set divisor
            self.outb(regs::LCR, lcr::DLAB);

            // Set divisor
            self.outb(regs::DLL, (divisor & 0xFF) as u8);
            self.outb(regs::DLH, ((divisor >> 8) & 0xFF) as u8);

            // Set 8N1, disable DLAB
            self.outb(regs::LCR, lcr::MODE_8N1);

            // Enable and clear FIFOs, 14-byte trigger
            self.outb(
                regs::FCR,
                fcr::ENABLE | fcr::CLEAR_RX | fcr::CLEAR_TX | fcr::TRIGGER_14,
            );

            // Enable DTR, RTS, and OUT2 (for interrupts)
            self.outb(regs::MCR, mcr::DTR | mcr::RTS | mcr::OUT2);
        }
    }

    /// Write a byte (polled, waits for TX ready)
    fn write_byte(&self, byte: u8) {
        unsafe {
            // Wait for transmit buffer empty
            while self.inb(regs::LSR) & lsr::THRE == 0 {
                core::hint::spin_loop();
            }
            // Send byte
            self.outb(regs::THR, byte);
        }
    }

    /// Read a byte if available
    fn read_byte(&self) -> Option<u8> {
        unsafe { (self.inb(regs::LSR) & lsr::DR != 0).then(|| self.inb(regs::RBR)) }
    }

    /// Drain the receive FIFO into `tty`'s flip buffer (IRQ context;
    /// Linux serial8250_rx_chars). True if the UART had an interrupt
    /// pending
    fn rx_chars(&self, tty: &Tty) -> bool {
        // SAFETY: IIR is a register of this UART
        if unsafe { self.inb(regs::IIR) } & iir::NO_INT != 0 {
            return false;
        }
        let mut buf = [0u8; 64];
        loop {
            let mut n = 0;
            while n < buf.len()
                && let Some(b) = self.read_byte()
            {
                buf[n] = b;
                n += 1;
            }
            crate::tty::flip::receive(tty, &buf[..n]);
            if n < buf.len() {
                return true;
            }
        }
    }

    /// Enable the receive interrupt (IER.RDI; MCR.OUT2 is set already)
    fn enable_rx_irq(&self) {
        self.uart
            .locked(|| self.set_ier(self.ier.load(Ordering::Relaxed) | ier::RDI));
    }

    /// Wait for transmitter to be completely empty (all bytes sent)
    fn flush(&self) {
        unsafe {
            // Wait for TEMT (Transmitter Empty) - both THR and shift register empty
            while self.inb(regs::LSR) & lsr::TEMT == 0 {
                core::hint::spin_loop();
            }
        }
    }

    /// Write byte to I/O port
    ///
    /// # Safety
    /// `offset` is a register of this UART's port range.
    #[inline]
    unsafe fn outb(&self, offset: u16, value: u8) {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.port.load(Ordering::Relaxed) + offset,
                in("al") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Read byte from I/O port
    ///
    /// # Safety
    /// As [`Self::outb`].
    #[inline]
    unsafe fn inb(&self, offset: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") self.port.load(Ordering::Relaxed) + offset,
                out("al") value,
                options(nostack, preserves_flags)
            );
        }
        value
    }
}

/// The 8250's transmitter (Linux serial8250_pops), under the port lock
impl UartOps for SerialTty {
    fn tx_burst(&self, _from_irq: bool) -> usize {
        // SAFETY: LSR is a register of this UART
        if unsafe { self.inb(regs::LSR) } & lsr::THRE != 0 {
            TX_LOADSZ
        } else {
            0
        }
    }

    fn tx_put(&self, b: u8) {
        // SAFETY: THR is a register of this UART, empty (tx_burst)
        unsafe { self.outb(regs::THR, b) };
    }

    /// Linux serial8250_tx_chars: the x_char alone in its round
    fn xchar_ends_round(&self) -> bool {
        true
    }

    /// Linux serial8250_start_tx / __stop_tx: IER.THRI
    fn tx_irq(&self, on: bool) {
        let v = self.ier.load(Ordering::Relaxed);
        self.set_ier(if on { v | ier::THRI } else { v & !ier::THRI });
    }

    fn console_putc(&self, b: u8) {
        self.write_byte(b);
    }

    fn tx_drain(&self) {
        SerialTty::flush(self);
    }

    /// Linux serial8250_console_write: IER saved and cleared
    fn console_begin(&self) -> u32 {
        let v = self.ier.load(Ordering::Relaxed);
        // SAFETY: IER is a register of this UART
        unsafe { self.outb(regs::IER, 0) };
        u32::from(v)
    }

    /// ... and restored once the transmitter is empty
    fn console_end(&self, saved: u32) {
        // SAFETY: IER is a register of this UART
        unsafe { self.outb(regs::IER, saved as u8) };
    }

    /// Linux serial8250_do_startup: FIFOs cleared; no UART if LSR reads
    /// 0xff (ENODEV); then the line set up (uart_change_line_settings:
    /// 115200 8N1 here), DTR, RTS and OUT2 raised, and the receive
    /// interrupt enabled if the port takes input by interrupt
    fn startup(&self) -> Result<(), KernelError> {
        // SAFETY: FCR and LSR are registers of this UART
        unsafe {
            self.outb(regs::FCR, fcr::ENABLE | fcr::CLEAR_RX | fcr::CLEAR_TX);
            if self.inb(regs::LSR) == 0xff {
                return Err(KernelError::NoDevice);
            }
        }
        self.init_hardware(115200);
        if self.uart.irq_on() {
            self.enable_rx_irq();
        }
        Ok(())
    }

    /// Linux serial8250_do_shutdown: interrupts off, OUT2 dropped, the
    /// FIFOs cleared (the caller holds no port lock)
    fn shutdown(&self) {
        self.uart.locked(|| self.set_ier(0));
        // SAFETY: MCR and FCR are registers of this UART
        unsafe {
            self.outb(regs::MCR, mcr::DTR | mcr::RTS);
            self.outb(regs::FCR, fcr::ENABLE | fcr::CLEAR_RX | fcr::CLEAR_TX);
            self.outb(regs::FCR, 0);
        }
    }

    /// Linux serial8250_request_port -> serial8250_request_std_resource
    fn request_port(&self) -> Result<(), KernelError> {
        let base = self.port.load(Ordering::Relaxed);
        crate::base::resource::request_region(u64::from(base), 8, "serial")
    }

    /// Linux serial8250_release_port -> serial8250_release_std_resource
    fn release_port(&self) {
        let base = self.port.load(Ordering::Relaxed);
        crate::base::resource::release_region(u64::from(base), 8);
    }

    /// The registers move with the port (Linux reads uport->iobase)
    fn set_port(&self, iobase: u32, _type: i32) {
        self.port.store(iobase as u16, Ordering::Relaxed);
    }

    fn arm_poll(&self) {
        core::pin::Pin::static_ref(self.poll).mod_timer(crate::task::percpu::get_ticks() + 1);
    }

    /// Linux serial8250_verify_port: a type of uart_config (PORT_BCM7271
    /// the last), not Cirrus or Startech
    fn verify_port(&self, ss: &crate::tty::SerialStruct) -> Result<(), KernelError> {
        const NR_TYPES: i32 = 77;
        if ss.irq < 0
            || ss.baud_base < 9600
            || ss.type_ < PORT_UNKNOWN
            || ss.type_ >= NR_TYPES
            || ss.type_ == PORT_CIRRUS
            || ss.type_ == PORT_STARTECH
        {
            return Err(KernelError::InvalidArgument);
        }
        Ok(())
    }
}

impl TtyDriver for SerialTty {
    /// Linux uart_write: into the transmit buffer, the transmitter
    /// started
    fn write(&self, tty: &Tty, data: &[u8]) -> Result<usize, KernelError> {
        let (n, wake) = self.uart.write(self, data);
        if wake {
            tty.write_wakeup();
        }
        Ok(n)
    }

    /// Linux uart_stop
    fn stop(&self) {
        self.uart.stop(self);
    }

    /// Linux uart_start (the tty layer wakes writers after)
    fn start(&self) {
        self.uart.start(self);
    }

    /// Linux uart_send_xchar
    fn send_xchar(&self, tty: &Tty, ch: u8) {
        if self.uart.send_xchar(self, ch) {
            tty.write_wakeup();
        }
    }

    /// Linux uart_throttle
    fn throttle(&self, tty: &Tty) {
        if let Some(ch) = crate::tty::serial_core::ixoff_char(tty, true) {
            self.send_xchar(tty, ch);
        }
    }

    /// Linux uart_unthrottle
    fn unthrottle(&self, tty: &Tty) {
        if let Some(ch) = crate::tty::serial_core::ixoff_char(tty, false) {
            self.send_xchar(tty, ch);
        }
    }

    fn flush(&self) {
        SerialTty::flush(self);
    }

    fn write_room(&self) -> usize {
        self.uart.write_room()
    }

    fn chars_in_buffer(&self) -> usize {
        self.uart.chars_in_buffer()
    }

    fn flush_buffer(&self) {
        self.uart.flush_buffer();
    }

    /// Linux uart_port_activate
    fn activate(&self, admin: bool) -> Result<bool, KernelError> {
        self.uart.activate(self, admin)
    }

    /// Linux uart_hangup
    fn hangup(&self, up: bool) {
        self.uart.hangup(self, up);
    }

    /// Linux uart_tty_port_shutdown
    fn shutdown(&self, down: bool) {
        self.uart.shutdown(self, down);
    }

    /// Linux serial8250_console_write: under the port lock
    fn console_write(&self, data: &[u8]) {
        self.uart.console_write(self, data);
    }

    /// Linux uart_get_info
    fn get_serial(
        &self,
        port: &crate::tty::TtyPort,
    ) -> Result<crate::tty::SerialStruct, KernelError> {
        Ok(self.uart.get_info(port))
    }

    /// Linux uart_set_info
    fn set_serial(
        &self,
        tty: &Tty,
        port: &mut crate::tty::TtyPort,
        ss: &crate::tty::SerialStruct,
        users: usize,
    ) -> Result<(), KernelError> {
        let admin = crate::task::capable(crate::task::CAP_SYS_ADMIN);
        self.uart.set_info(self, tty, port, ss, users, admin)
    }
}

/// Standard COM port addresses
pub mod ports {
    /// COM1 - Primary serial port
    pub const COM1: u16 = 0x3F8;
    /// COM2 - Secondary serial port
    pub const COM2: u16 = 0x2F8;
    /// COM3 - Tertiary serial port
    pub const COM3: u16 = 0x3E8;
    /// COM4 - Quaternary serial port
    pub const COM4: u16 = 0x2E8;
}

/// Static serial hardware driver instances for standard COM ports
static SERIAL_DRIVER_S0: SerialTty = SerialTty::new(0, ports::COM1, 4, &POLL_S0);
static SERIAL_DRIVER_S1: SerialTty = SerialTty::new(1, ports::COM2, 3, &POLL_S1);

/// The ports' transmitter poll timers (Linux up->timer), for a port
/// without an interrupt
static POLL_S0: TimerList = TimerList::new(serial8250_timeout, TIMER_HARD);
static POLL_S1: TimerList = TimerList::new(serial8250_timeout, TIMER_HARD);

/// The 8250 ports, each driver with its tty (Linux serial8250_ports)
static PORTS: [(&SerialTty, &Tty); 2] = [
    (&SERIAL_DRIVER_S0, &SERIAL_TTY_S0),
    (&SERIAL_DRIVER_S1, &SERIAL_TTY_S1),
];

/// A port's poll timer (Linux serial8250_timeout): the port is the one
/// whose timer fired (Linux from_timer(up, t, timer))
fn serial8250_timeout(t: &TimerList) {
    let Some(&(drv, tty)) = PORTS.iter().find(|(d, _)| core::ptr::eq(d.poll, t)) else {
        return;
    };
    if drv.uart.poll_tx(drv) {
        tty.write_wakeup();
    }
}

/// Static TTY instances wrapping the serial drivers
///
/// These provide the proper layer separation: Console → TTY → Driver
pub static SERIAL_TTY_S0: Tty = Tty::new("ttyS0", ttys_dev(0), &SERIAL_DRIVER_S0);
pub static SERIAL_TTY_S1: Tty = Tty::new("ttyS1", ttys_dev(1), &SERIAL_DRIVER_S1);

/// ttyS<n> is (4, 64 + n) (Linux devices.txt)
const fn ttys_dev(n: u16) -> DevId {
    DevId::new(major::TTYS, 64 + n)
}

/// Initialize the primary serial console
///
/// This initializes COM1 hardware and registers the TTY as a console
/// with Fallback priority. USB serial (if present) will have Normal
/// priority and take precedence.
///
/// Marked as BOOT console - this is the early serial output during boot.
/// When a real console (graphics, USB serial) registers with CONSDEV,
/// boot consoles are typically demoted or unregistered.
pub fn init_serial_console() {
    use crate::console::ConsoleFlags;

    // Initialize hardware
    SERIAL_DRIVER_S0.init_hardware(115200);

    // Register the TTY (not raw driver) as console with Fallback priority
    // BOOT flag indicates this is an early boot console
    register_console(
        &SERIAL_TTY_S0,
        ConsolePriority::Fallback,
        ConsoleFlags::BOOT,
    );
}

/// Write a byte directly to COM1 for panic output
///
/// This bypasses all locking and goes directly to hardware.
/// Only use during panic when normal printk path may deadlock.
pub fn write_byte_com1(byte: u8) {
    SERIAL_DRIVER_S0.write_byte(byte);
}

/// COM1's interrupt handler (IRQ context; Linux serial8250_handle_irq):
/// input to ttyS0, then the transmitter refilled under the port lock,
/// its writers woken after
fn com1_irq(_irq: u32) -> IrqReturn {
    if !SERIAL_DRIVER_S0.rx_chars(&SERIAL_TTY_S0) {
        return IrqReturn::None;
    }
    if SERIAL_DRIVER_S0.uart.interrupt_tx(&SERIAL_DRIVER_S0) {
        SERIAL_TTY_S0.write_wakeup();
    }
    IrqReturn::Handled
}

/// Take COM1's input by interrupt (Linux serial8250_startup); `irq` is
/// its PIC line. None without it
fn rx_irq_init(irq: u32) -> Option<IrqRegistration<IrqFn>> {
    let h = try_arc(IrqFn(com1_irq)).ok()?;
    let reg = crate::irq::request_irq(irq, h)
        .inspect_err(|e| crate::printkln!("ttyS0: no IRQ {}: {:?}", irq, e))
        .ok()?;
    SERIAL_DRIVER_S0.enable_rx_irq();
    // The transmitter drains by interrupt from here
    SERIAL_DRIVER_S0.uart.set_irq(&SERIAL_DRIVER_S0, true);
    Some(reg)
}

/// The serial ports' ttys (Linux serial8250 ports)
pub fn serial_ttys() -> &'static [&'static Tty] {
    static TTYS: [&Tty; 2] = [&SERIAL_TTY_S0, &SERIAL_TTY_S1];
    &TTYS
}

/// The 8250 platform driver (Linux serial8250_isa_driver): its ports'
/// ttys go below the device; COM1's input by interrupt
pub static SERIAL8250_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "serial8250",
    &crate::base::platform::PLATFORM_BUS,
    None,
    &crate::base::platform::Names(&["serial8250"]),
    serial8250_probe,
);

/// Stop taking COM1's input by interrupt (Linux serial8250_shutdown:
/// IER cleared, then free_irq, which waits out a running handler)
fn rx_irq_exit(irq: IrqRegistration<IrqFn>) {
    SERIAL_DRIVER_S0.uart.set_irq(&SERIAL_DRIVER_S0, false);
    SERIAL_DRIVER_S0.uart.locked(|| SERIAL_DRIVER_S0.set_ier(0));
    drop(irq);
}

/// A bound 8250 device: COM1's IRQ, its ports' tty devices
struct Serial8250 {
    /// Set by probe, taken by remove (spin leaf: dropped unlocked)
    irq: Mutex<Option<IrqRegistration<IrqFn>>>,
    ttys: alloc::vec::Vec<alloc::sync::Arc<crate::base::Device>>,
}

impl crate::base::Bound for Serial8250 {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux serial8250_remove, uart_remove_one_port per port: its tty
    /// device goes, its tty is hung up (tty_port_tty_vhangup), its
    /// console goes, its interrupt is off
    fn remove(&self) {
        for t in self.ttys.iter().rev() {
            t.del();
        }
        for tty in serial_ttys().iter().rev() {
            tty.hangup(false);
        }
        crate::console::unregister_console(SERIAL_TTY_S0.name());
        let irq = self.irq.lock().take();
        if let Some(irq) = irq {
            rx_irq_exit(irq);
        }
        // Linux uart_remove_one_port: a port of known type releases
        // its registers
        for d in [&SERIAL_DRIVER_S0, &SERIAL_DRIVER_S1] {
            if d.uart.port().1 != PORT_UNKNOWN {
                d.release_port();
            }
        }
    }
}

fn serial8250_probe(
    dev: &alloc::sync::Arc<crate::base::Device>,
) -> Result<alloc::boxed::Box<dyn crate::base::Bound>, crate::util::error::KernelError> {
    // Allocated first, so ENOMEM leaves nothing registered
    let mut port = try_box(Serial8250 {
        irq: Mutex::new(None),
        ttys: alloc::vec::Vec::new(),
    })?;
    // Each port's registers (Linux serial8250_request_std_resource:
    // request_region(iobase, 8, "serial"))
    let ports = [&SERIAL_DRIVER_S0, &SERIAL_DRIVER_S1];
    let known = |d: &SerialTty| d.uart.port().1 != PORT_UNKNOWN;
    for (i, d) in ports.iter().enumerate() {
        if !known(d) {
            continue;
        }
        if let Err(e) = d.request_port() {
            for done in ports[..i].iter().filter(|d| known(d)) {
                done.release_port();
            }
            return Err(e);
        }
    }
    // Registered at boot already, or again after an unbind (Linux
    // uart_add_one_port's uart_configure_port -> register_console)
    register_console(
        &SERIAL_TTY_S0,
        ConsolePriority::Fallback,
        crate::console::ConsoleFlags::BOOT,
    );
    // COM2 is set up as COM1 was at boot (Linux serial8250_config_port);
    // it has no interrupt: a timer drains its transmitter
    SERIAL_DRIVER_S1.init_hardware(115200);
    let irq = crate::base::platform::pdev(dev).and_then(|p| p.irq);
    *port.irq.get_mut() = irq.and_then(rx_irq_init);
    port.ttys = serial_ttys()
        .iter()
        .filter_map(|t| crate::tty::tty_register_device(t, dev))
        .collect();
    Ok(port)
}

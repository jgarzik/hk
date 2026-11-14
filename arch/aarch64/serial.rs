//! PL011 UART driver for AArch64
//!
//! A polled driver for the ARM PL011 UART found in QEMU's virt machine
//! and many real ARM platforms: the early console, and the tty ttyAMA0
//! (Linux amba-pl011).

use core::fmt;

use crate::fs::chardev::{DevId, major};
use crate::irq::{IrqFn, IrqRegistration, IrqReturn};
use crate::sync::spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::time::timer::{TIMER_HARD, TimerList};
use crate::tty::serial_core::{
    PORT_AMBA, PORT_UNKNOWN, UPF_BOOT_AUTOCONF, UPIO_MEM, UartCfg, UartDesc, UartOps, UartPort,
};
use crate::tty::{Tty, TtyDriver};
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};
use core::ptr::{read_volatile, write_volatile};

/// PL011 UART physical address on QEMU virt machine (Linux mapbase)
const PL011_PHYS: u64 = 0x0900_0000;
/// ... and where the kernel maps it
const PL011_BASE: usize = super::paging::io_va(PL011_PHYS) as usize;

/// PL011 register offsets
mod regs {
    /// Data Register (read/write)
    pub const DR: usize = 0x000;
    /// Flag Register (read only)
    pub const FR: usize = 0x018;
    /// Integer Baud Rate Register
    pub const IBRD: usize = 0x024;
    /// Fractional Baud Rate Register
    pub const FBRD: usize = 0x028;
    /// Line Control Register
    pub const LCR_H: usize = 0x02C;
    /// Control Register
    pub const CR: usize = 0x030;
    /// Interrupt Mask Set/Clear Register
    pub const IMSC: usize = 0x038;
    /// Masked Interrupt Status Register
    pub const MIS: usize = 0x040;
}

/// Flag Register bits
mod fr {
    /// Receive FIFO empty
    pub const RXFE: u32 = 1 << 4;
    /// Transmit FIFO full
    pub const TXFF: u32 = 1 << 5;
    /// UART busy
    pub const BUSY: u32 = 1 << 3;
}

/// Interrupt bits (IMSC, MIS)
mod int {
    /// Receive (FIFO level reached)
    pub const RX: u32 = 1 << 4;
    /// Transmit (FIFO at or below its level; Linux UART011_TXIS)
    pub const TX: u32 = 1 << 5;
    /// Receive timeout (FIFO not empty, idle line)
    pub const RT: u32 = 1 << 6;
}

/// Bytes sent per TX interrupt: half the FIFO (Linux pl011_tx_chars'
/// fifosize >> 1)
const TX_BURST: usize = 8;

/// Line Control Register bits
mod lcr {
    /// Enable FIFOs
    pub const FEN: u32 = 1 << 4;
    /// Word length 8 bits
    pub const WLEN_8: u32 = 0b11 << 5;
}

/// Control Register bits
mod cr {
    /// UART enable
    pub const UARTEN: u32 = 1 << 0;
    /// Transmit enable
    pub const TXE: u32 = 1 << 8;
    /// Receive enable
    pub const RXE: u32 = 1 << 9;
}

/// PL011 UART driver
///
/// # Invariants
/// `base` is the PL011's register block, mapped for the kernel's life.
struct Pl011 {
    base: usize,
    /// Its port lock and transmit buffer (Linux uart_port)
    uart: UartPort,
    /// IMSC as last written (Linux uap->im), under the port lock
    im: AtomicU32,
}

impl Pl011 {
    /// The driver for the UART at `base` (only `UART`, at PL011_BASE)
    const fn new(base: usize) -> Self {
        // INVARIANT: PL011_BASE is mapped by the early page tables and
        // stays mapped
        Self {
            base,
            uart: UartPort::new(
                UartDesc {
                    type_: PORT_AMBA,
                    line: 0,
                    iobase: 0,
                    mapbase: PL011_PHYS,
                    iotype: UPIO_MEM,
                    regshift: 0,
                },
                // Linux pl011_probe: the APB clock (24 MHz on QEMU
                // virt), an r1 PL011's 16-byte FIFO (get_fifosize_arm);
                // the interrupt is known at probe
                UartCfg {
                    irq: 0,
                    flags: UPF_BOOT_AUTOCONF,
                    uartclk: 24_000_000,
                    custom_divisor: 0,
                    fifosize: 16,
                },
            ),
            im: AtomicU32::new(0),
        }
    }

    /// Write IMSC (under the port lock)
    fn set_im(&self, v: u32) {
        self.im.store(v, Ordering::Relaxed);
        self.write_reg(regs::IMSC, v);
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: usize) -> u32 {
        // SAFETY: a register of the block (type invariant)
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: usize, value: u32) {
        // SAFETY: a register of the block (type invariant)
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Initialize the UART
    ///
    /// Note: QEMU's PL011 comes pre-initialized, but we configure it anyway
    /// for completeness and to ensure consistent behavior.
    pub fn init(&self) {
        // Disable UART while configuring
        self.write_reg(regs::CR, 0);

        // Wait for any current transmission to complete
        while self.read_reg(regs::FR) & fr::BUSY != 0 {
            core::hint::spin_loop();
        }

        // Disable all interrupts
        self.write_reg(regs::IMSC, 0);

        // Set baud rate to 115200 (assuming 24MHz clock, QEMU default)
        // Divisor = 24000000 / (16 * 115200) = 13.0208
        // IBRD = 13, FBRD = round(0.0208 * 64) = 1
        self.write_reg(regs::IBRD, 13);
        self.write_reg(regs::FBRD, 1);

        // Set 8N1, enable FIFOs
        self.write_reg(regs::LCR_H, lcr::WLEN_8 | lcr::FEN);

        // Enable UART, TX, and RX
        self.write_reg(regs::CR, cr::UARTEN | cr::TXE | cr::RXE);
    }

    /// Write a single byte, waiting if necessary
    pub fn write_byte(&self, byte: u8) {
        // Wait until TX FIFO has space
        while self.read_reg(regs::FR) & fr::TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(regs::DR, u32::from(byte));
    }

    /// Drain the receive FIFO into `tty`'s flip buffer (IRQ context;
    /// Linux pl011_rx_chars). True if a receive interrupt was pending
    fn rx_chars(&self, tty: &Tty) -> bool {
        if self.read_reg(regs::MIS) & (int::RX | int::RT) == 0 {
            return false;
        }
        let mut buf = [0u8; 64];
        loop {
            let mut n = 0;
            while n < buf.len() && self.read_reg(regs::FR) & fr::RXFE == 0 {
                // The low byte is the character, the bits above its errors
                buf[n] = (self.read_reg(regs::DR) & 0xff) as u8;
                n += 1;
            }
            crate::tty::flip::receive(tty, &buf[..n]);
            if n < buf.len() {
                break;
            }
        }
        // RX/RT are not written to ICR (Linux pl011_int): draining the
        // FIFO clears them, and a byte arriving after the last RXFE check
        // keeps its interrupt
        true
    }

    /// Write a string
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

/// Global UART instance (its methods take `&self`: MMIO only)
static UART: Pl011 = Pl011::new(PL011_BASE);

/// The PL011's transmitter (Linux amba_pl011_pops), under the port lock
impl UartOps for Pl011 {
    /// Half the FIFO from the interrupt; else until the FIFO is full
    fn tx_burst(&self, from_irq: bool) -> usize {
        if from_irq { TX_BURST } else { usize::MAX }
    }

    fn tx_full(&self) -> bool {
        self.read_reg(regs::FR) & fr::TXFF != 0
    }

    fn tx_put(&self, b: u8) {
        self.write_reg(regs::DR, u32::from(b));
    }

    /// Linux pl011_start_tx_pio / pl011_stop_tx: IMSC.TXIM
    fn tx_irq(&self, on: bool) {
        let v = self.im.load(Ordering::Relaxed);
        self.set_im(if on { v | int::TX } else { v & !int::TX });
    }

    fn console_putc(&self, b: u8) {
        self.write_byte(b);
    }

    fn tx_drain(&self) {
        TtyDriver::flush(self);
    }

    fn arm_poll(&self) {
        core::pin::Pin::static_ref(&POLL).mod_timer(crate::task::percpu::get_ticks() + 1);
    }

    /// Linux pl011_verify_port: an AMBA port at its own address
    fn verify_port(&self, ss: &crate::tty::SerialStruct) -> Result<(), KernelError> {
        if (ss.type_ != PORT_UNKNOWN && ss.type_ != PORT_AMBA)
            || ss.irq < 0
            || ss.baud_base < 9600
            || ss.iomem_base != PL011_PHYS
        {
            return Err(KernelError::InvalidArgument);
        }
        Ok(())
    }
}

impl TtyDriver for Pl011 {
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
        while self.read_reg(regs::FR) & fr::BUSY != 0 {
            core::hint::spin_loop();
        }
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

    /// Linux uart_tty_port_shutdown
    fn shutdown(&self, console: bool) {
        self.uart.shutdown(self, console);
    }

    /// Linux pl011_console_write: under the port lock
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
        port: &mut crate::tty::TtyPort,
        ss: &crate::tty::SerialStruct,
        users: usize,
    ) -> Result<(), KernelError> {
        let admin = crate::task::capable(crate::task::CAP_SYS_ADMIN);
        self.uart.set_info(self, port, ss, users > 0, users, admin)
    }
}

/// Polls the transmitter while the PL011 has no interrupt
static POLL: TimerList = TimerList::new(poll, TIMER_HARD);

fn poll(_t: &TimerList) {
    if UART.uart.poll_tx(&UART) {
        TTY_AMA0.write_wakeup();
    }
}

/// The PL011's tty, ttyAMA0 = (204, 64) (Linux devices.txt)
pub static TTY_AMA0: Tty = Tty::new("ttyAMA0", DevId::new(major::AMBA, 64), &UART);

/// The serial ports' ttys
pub fn serial_ttys() -> &'static [&'static Tty] {
    static TTYS: [&Tty; 1] = [&TTY_AMA0];
    &TTYS
}

/// The PL011's interrupt handler (IRQ context; Linux pl011_int): input
/// to ttyAMA0, then the transmitter refilled under the port lock, its
/// writers woken after
fn pl011_irq(_irq: u32) -> IrqReturn {
    let rx = UART.rx_chars(&TTY_AMA0);
    let tx = UART.read_reg(regs::MIS) & int::TX != 0;
    if tx && UART.uart.interrupt_tx(&UART) {
        TTY_AMA0.write_wakeup();
    }
    (rx || tx).into()
}

/// Take input by interrupt (Linux pl011_startup); `irq` is the GIC
/// INTID. None without it
fn rx_irq_init(irq: u32) -> Option<IrqRegistration<IrqFn>> {
    UART.uart.set_irq_nr(irq as i32);
    let h = try_arc(IrqFn(pl011_irq)).ok()?;
    let reg = crate::irq::request_irq(irq, h)
        .inspect_err(|e| crate::printkln!("ttyAMA0: no IRQ {}: {:?}", irq, e))
        .ok()?;
    UART.uart
        .locked(|| UART.set_im(UART.im.load(Ordering::Relaxed) | int::RX | int::RT));
    // The transmitter drains by interrupt from here
    UART.uart.set_irq(&UART, true);
    Some(reg)
}

/// Stop taking input by interrupt (Linux pl011_shutdown: IMSC cleared,
/// then free_irq, which waits out a running handler)
fn rx_irq_exit(irq: IrqRegistration<IrqFn>) {
    UART.uart.set_irq(&UART, false);
    UART.uart.locked(|| UART.set_im(0));
    drop(irq);
}

/// The PL011 is the earlycon until ttyAMA0 registers
impl crate::arch::EarlyConOps for super::Aarch64Arch {
    const EARLYCON: bool = true;

    fn early_write(bytes: &[u8]) {
        if let Ok(s) = core::str::from_utf8(bytes) {
            write_str(s);
        } else {
            bytes.iter().for_each(|&b| write_byte(b));
        }
    }
}

/// Make ttyAMA0 a console (Linux pl011 console; it is /dev/console's
/// tty). Printk keeps writing the UART directly
pub fn register_console() {
    use crate::console::{ConsoleFlags, ConsolePriority};
    crate::console::register_console(&TTY_AMA0, ConsolePriority::Fallback, ConsoleFlags::empty());
}

/// Initialize the serial console
pub fn init() {
    UART.init();
}

/// Write a string to the serial console
pub fn write_str(s: &str) {
    UART.write_str(s);
}

/// Write a single byte to the serial console
pub fn write_byte(byte: u8) {
    UART.write_byte(byte);
}

/// Boot-time writer for direct serial output
///
/// This implements fmt::Write to allow formatted output during early boot
/// when the printk buffer may not be flushed to console yet.
pub struct BootWriter;

impl fmt::Write for BootWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Macro for early boot printing before the kernel heap is available
#[macro_export]
macro_rules! early_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::arch::aarch64::serial::BootWriter, $($arg)*);
    }};
}

/// Macro for early boot printing with newline
#[macro_export]
macro_rules! early_println {
    () => {
        $crate::early_print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::early_print!($($arg)*);
        $crate::early_print!("\n");
    }};
}

/// The PL011 driver (Linux amba-pl011 "uart-pl011"): the UART is set up
/// at boot; probing makes its tty a console and takes input by IRQ
pub static PL011_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "uart-pl011",
    &crate::base::platform::PLATFORM_BUS,
    None,
    &crate::base::platform::Names(&["arm,pl011"]),
    pl011_probe,
);

/// A bound PL011: its IRQ and tty device
struct Pl011Port {
    /// Set by probe, taken by remove (spin leaf: dropped unlocked)
    irq: Mutex<Option<IrqRegistration<IrqFn>>>,
    tty: Option<alloc::sync::Arc<crate::base::Device>>,
}

impl crate::base::Bound for Pl011Port {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux pl011_remove, uart_remove_one_port: the tty device and
    /// console go, the interrupt is off (no hangup of an open tty:
    /// BUGS.md). Printk then has no console, as on Linux
    fn remove(&self) {
        if let Some(t) = &self.tty {
            t.del();
        }
        crate::console::unregister_console(TTY_AMA0.name());
        let irq = self.irq.lock().take();
        if let Some(irq) = irq {
            rx_irq_exit(irq);
        }
    }
}

fn pl011_probe(
    dev: &alloc::sync::Arc<crate::base::Device>,
) -> Result<alloc::boxed::Box<dyn crate::base::Bound>, crate::util::error::KernelError> {
    // Allocated first, so ENOMEM leaves nothing registered
    let mut port = try_box(Pl011Port {
        irq: Mutex::new(None),
        tty: None,
    })?;
    register_console();
    let irq = crate::base::platform::pdev(dev).and_then(|p| p.irq);
    *port.irq.get_mut() = irq.and_then(rx_irq_init);
    port.tty = crate::tty::tty_register_device(&TTY_AMA0, dev);
    Ok(port)
}

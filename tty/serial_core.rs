//! UART port lock (Linux drivers/tty/serial/serial_core.c,
//! uart_port.lock)
//!
//! A UART's console writes and tty writes go out under its port lock,
//! so a console message never interleaves with a tty write's bytes
//! (Linux serial8250_console_write and pl011_console_write take the
//! port lock irqsave, uart_write takes it to queue the tty's bytes).
//! hk's UART output is polled: a tty write takes the lock per FIFO-sized
//! chunk, which bounds how long interrupts stay off.

use crate::sync::IrqSpinlock;

/// Bytes of a tty write sent per hold of the port lock (a 16550's
/// transmit FIFO)
const TX_CHUNK: usize = 16;

/// A UART's port lock (Linux uart_port.lock): an IRQ-safe leaf, taken
/// by console writes in any context and by tty writes
pub struct UartPort {
    lock: IrqSpinlock<()>,
}

impl UartPort {
    pub const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(()),
        }
    }

    /// A console write: under the port lock, only tried during an oops
    /// (output then goes out unlocked, as Linux's `locked = 0`), each LF
    /// preceded by CR (Linux uart_console_write), then `flush` waits
    /// for the transmitter to drain
    pub fn console_write(&self, data: &[u8], putc: impl Fn(u8), flush: impl Fn()) {
        let _g = if crate::printk::oops_in_progress() {
            self.lock.try_lock()
        } else {
            Some(self.lock.lock())
        };
        for &b in data {
            if b == b'\n' {
                putc(b'\r');
            }
            putc(b);
        }
        flush();
    }

    /// A tty write: `data` raw, a chunk per hold of the port lock
    pub fn write(&self, data: &[u8], putc: impl Fn(u8)) {
        for chunk in data.chunks(TX_CHUNK) {
            let _g = self.lock.lock();
            for &b in chunk {
                putc(b);
            }
        }
    }
}

impl Default for UartPort {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::UartPort;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// A console message written while another thread writes the tty
    /// comes out whole, never split by the tty's bytes
    #[test]
    fn console_not_interleaved() {
        let port = UartPort::new();
        let out = Mutex::new(Vec::new());
        let putc = |b: u8| out.lock().unwrap().push(b);
        std::thread::scope(|s| {
            s.spawn(|| {
                for _ in 0..200 {
                    port.write(&[b'a'; 64], putc);
                }
            });
            s.spawn(|| {
                for _ in 0..200 {
                    port.console_write(b"KSELFTEST:OK\n", putc, || {});
                }
            });
        });
        let out = out.into_inner().unwrap();
        let msg = b"KSELFTEST:OK\r\n";
        let whole = out.windows(msg.len()).filter(|w| *w == msg).count();
        assert_eq!(whole, 200);
    }
}

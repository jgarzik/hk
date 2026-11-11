//! /proc text generated into a fixed buffer (Linux fs/seq_file.c)
//!
//! A generator writes its whole file into a [`SeqBuf`] that never grows:
//! it may run under a spin lock or an RCU guard, where nothing may
//! allocate. When the text does not fit, the buffer is dropped and the
//! generator runs again into one twice the size (Linux seq_read, which
//! starts at a page and doubles its buffer when a record overflows).

use alloc::vec::Vec;
use core::fmt;

/// First buffer size (Linux seq_buf_alloc's PAGE_SIZE)
const FIRST: usize = 4096;

/// A fixed-size text buffer (Linux struct seq_file's buf/size/count)
///
/// # Invariants
/// `buf.capacity()` is the size it was made with: writes past it set
/// `overflow` and are dropped, never grown into.
pub struct SeqBuf {
    buf: Vec<u8>,
    overflow: bool,
}

impl SeqBuf {
    fn with_size(size: usize) -> Self {
        // Kernel-bounded: the generator's own data, doubled from a page
        Self {
            buf: Vec::with_capacity(size),
            overflow: false,
        }
    }

    /// The text did not fit (Linux seq_has_overflowed)
    pub fn has_overflowed(&self) -> bool {
        self.overflow
    }
}

impl fmt::Write for SeqBuf {
    /// Linux seq_printf: all of `s` or nothing, the overflow recorded
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.overflow || self.buf.capacity() - self.buf.len() < s.len() {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Generate a file with `show`, which writes all of it into the buffer
/// it is given (it may hold a lock or an RCU guard meanwhile: the
/// buffer never allocates); rerun with twice the buffer while it
/// overflows (Linux seq_read's retry with a doubled buffer)
pub fn generate(show: impl Fn(&mut SeqBuf)) -> Vec<u8> {
    let mut size = FIRST;
    loop {
        let mut m = SeqBuf::with_size(size);
        show(&mut m);
        if !m.has_overflowed() {
            return m.buf;
        }
        size = size.saturating_mul(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    /// Text larger than a page is generated whole, by reruns; a short
    /// one in one pass
    #[test]
    fn reruns_until_it_fits() {
        let runs = core::cell::Cell::new(0);
        let out = generate(|m| {
            runs.set(runs.get() + 1);
            for i in 0..1000 {
                let _ = writeln!(m, "line {i:>8}");
            }
        });
        assert_eq!(out.len(), 1000 * 14);
        assert!(out.ends_with(b"line      999\n"));
        assert_eq!(runs.get(), 3);
        let out = generate(|m| {
            let _ = write!(m, "short");
        });
        assert_eq!(out, b"short");
    }

    /// A write that does not fit is dropped whole and marks overflow
    #[test]
    fn overflow_drops_the_write() {
        let mut m = SeqBuf::with_size(8);
        let cap = m.buf.capacity();
        assert!(m.write_str("abc").is_ok());
        let long = "x".repeat(cap);
        assert!(m.write_str(&long).is_err());
        assert!(m.has_overflowed() && m.buf == b"abc");
    }
}

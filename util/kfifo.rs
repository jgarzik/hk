//! Fixed-size byte FIFO (Linux lib/kfifo.c, a byte kfifo): `N`, a power
//! of two, bytes inline, no allocation. The caller locks it (Linux
//! kfifo_in_locked / kfifo_out_locked take the lock around the plain
//! calls).

/// A ring of `N` bytes; `in_` and `out` count bytes ever added and
/// removed, wrapping, so `in_ - out` is the length (Linux struct
/// __kfifo)
pub struct Kfifo<const N: usize> {
    in_: usize,
    out: usize,
    data: [u8; N],
}

impl<const N: usize> Kfifo<N> {
    const MASK: usize = {
        assert!(N.is_power_of_two());
        N - 1
    };

    /// An empty FIFO
    pub const fn new() -> Self {
        Self {
            in_: 0,
            out: 0,
            data: [0; N],
        }
    }

    /// Bytes queued (Linux kfifo_len)
    pub fn len(&self) -> usize {
        self.in_.wrapping_sub(self.out)
    }

    /// Nothing queued (Linux kfifo_is_empty)
    pub fn is_empty(&self) -> bool {
        self.in_ == self.out
    }

    /// Queue as much of `buf` as fits; the rest is dropped (Linux
    /// kfifo_in). Returns the bytes queued
    pub fn push(&mut self, buf: &[u8]) -> usize {
        let n = buf.len().min(N - self.len());
        let off = self.in_ & Self::MASK;
        let first = n.min(N - off);
        self.data[off..off + first].copy_from_slice(&buf[..first]);
        self.data[..n - first].copy_from_slice(&buf[first..n]);
        self.in_ = self.in_.wrapping_add(n);
        n
    }

    /// Take up to `buf.len()` bytes into `buf` (Linux kfifo_out).
    /// Returns the bytes taken
    pub fn pop(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len());
        let off = self.out & Self::MASK;
        let first = n.min(N - off);
        buf[..first].copy_from_slice(&self.data[off..off + first]);
        buf[first..n].copy_from_slice(&self.data[..n - first]);
        self.out = self.out.wrapping_add(n);
        n
    }

    /// Drop everything queued (Linux kfifo_reset_out)
    pub fn reset(&mut self) {
        self.out = self.in_;
    }
}

impl<const N: usize> Default for Kfifo<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Kfifo;

    #[test]
    fn overflow_drops_the_tail() {
        let mut f = Kfifo::<8>::new();
        assert_eq!(f.push(b"0123456789"), 8);
        assert_eq!(f.len(), 8);
        assert_eq!(f.push(b"x"), 0);
        let mut b = [0u8; 16];
        assert_eq!(f.pop(&mut b), 8);
        assert_eq!(&b[..8], b"01234567");
        assert!(f.is_empty());
    }

    #[test]
    fn wraps_around() {
        let mut f = Kfifo::<8>::new();
        let mut b = [0u8; 8];
        assert_eq!(f.push(b"abcdef"), 6);
        assert_eq!(f.pop(&mut b[..4]), 4);
        assert_eq!(f.push(b"ghijk"), 5);
        assert_eq!(f.len(), 7);
        assert_eq!(f.pop(&mut b), 7);
        assert_eq!(&b[..7], b"efghijk");
        f.push(b"zz");
        f.reset();
        assert!(f.is_empty());
    }
}

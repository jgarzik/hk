//! An exec's argument or environment strings, packed (Linux bprm:
//! copy_strings puts them straight into the new stack's pages): each
//! NUL-terminated, back to back in one fallibly grown buffer, so the
//! kernel memory they take is their own bytes, not an allocation each

use alloc::vec::Vec;

use crate::uaccess::{UaccessArch, UaccessError, copy_from_user};
use crate::util::error::KernelError;

/// Strings, each with its NUL, in order
#[derive(Default)]
pub struct ArgStrings {
    buf: Vec<u8>,
    n: usize,
}

impl ArgStrings {
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            n: 0,
        }
    }

    /// How many strings
    pub const fn len(&self) -> usize {
        self.n
    }

    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Every string with its NUL, back to back (the block the new stack
    /// holds)
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// The strings, without their NULs
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.buf.split(|&b| b == 0).take(self.n)
    }

    /// Append `s` (which holds no NUL) and its NUL
    pub fn push(&mut self, s: &[u8]) -> Result<(), KernelError> {
        self.grow(s)?;
        self.grow(&[0])?;
        self.n += 1;
        Ok(())
    }

    /// Append every string of `other` but its first (Linux
    /// remove_arg_zero, for a script's interpreter)
    pub fn push_tail(&mut self, other: &ArgStrings) -> Result<(), KernelError> {
        let Some(z) = other.buf.iter().position(|&b| b == 0) else {
            return Ok(());
        };
        self.grow(&other.buf[z + 1..])?;
        self.n += other.n - 1;
        Ok(())
    }

    /// Append the user string at `ptr`, its NUL included at most `max`
    /// bytes (Linux strnlen_user + valid_arg_len), and charge its bytes
    /// with the NUL to `budget` (bprm_hit_stack_limit): E2BIG past
    /// either, EFAULT for an unreadable byte, ENOMEM
    pub fn push_user<A: UaccessArch>(
        &mut self,
        ptr: u64,
        max: usize,
        budget: &mut usize,
    ) -> Result<(), KernelError> {
        const PAGE: u64 = 4096;
        let mut at = ptr;
        let mut got = 0usize;
        let mut chunk = [0u8; 256];
        loop {
            if got >= max {
                return Err(KernelError::ArgListTooLong);
            }
            let to_page_end = (PAGE - at % PAGE) as usize;
            let n = chunk.len().min(to_page_end).min(max - got);
            copy_from_user::<A>(&mut chunk[..n], at, n).map_err(|e| match e {
                UaccessError::TooLong => KernelError::ArgListTooLong,
                _ => KernelError::BadAddress,
            })?;
            let end = chunk[..n].iter().position(|&b| b == 0);
            let take = end.map_or(n, |z| z + 1);
            *budget = budget
                .checked_sub(take)
                .ok_or(KernelError::ArgListTooLong)?;
            self.grow(&chunk[..take])?;
            got += take;
            if end.is_some() {
                self.n += 1;
                return Ok(());
            }
            at = at.checked_add(n as u64).ok_or(KernelError::BadAddress)?;
        }
    }

    fn grow(&mut self, b: &[u8]) -> Result<(), KernelError> {
        self.buf
            .try_reserve(b.len())
            .map_err(|_| KernelError::OutOfMemory)?;
        self.buf.extend_from_slice(b);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uaccess::HostUaccess;

    fn strs(v: &ArgStrings) -> Vec<&[u8]> {
        v.iter().collect()
    }

    #[test]
    fn packed_in_order() {
        let mut a = ArgStrings::new();
        a.push(b"one").unwrap();
        a.push(b"").unwrap();
        a.push(b"three").unwrap();
        assert_eq!(a.len(), 3);
        assert_eq!(a.bytes(), b"one\0\0three\0");
        assert_eq!(strs(&a), [&b"one"[..], b"", b"three"]);
        let mut b = ArgStrings::new();
        b.push(b"/bin/sh").unwrap();
        b.push_tail(&a).unwrap();
        assert_eq!(strs(&b), [&b"/bin/sh"[..], b"", b"three"]);
        b.push_tail(&ArgStrings::new()).unwrap();
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn user_strings_charged_and_bounded() {
        let s = b"hello\0";
        let mut a = ArgStrings::new();
        let mut budget = 100;
        a.push_user::<HostUaccess>(s.as_ptr() as u64, 6, &mut budget)
            .unwrap();
        assert_eq!(budget, 94);
        assert_eq!(strs(&a), [&b"hello"[..]]);
        // NUL included, longer than max: E2BIG
        let r = a.push_user::<HostUaccess>(s.as_ptr() as u64, 5, &mut budget);
        assert_eq!(r, Err(KernelError::ArgListTooLong));
        // Past the budget: E2BIG
        let mut small = 3;
        let r = a.push_user::<HostUaccess>(s.as_ptr() as u64, 100, &mut small);
        assert_eq!(r, Err(KernelError::ArgListTooLong));
    }
}

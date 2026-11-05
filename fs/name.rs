//! File names as bytes (Linux: a name is any bytes but '/' and NUL;
//! struct qstr, fs/namei.c getname)
//!
//! Names travel through the VFS, the dcache and every filesystem as
//! `&[u8]`; an owned one is a [`FileName`]. Nothing assumes UTF-8:
//! [`FileName`]'s `Display` escapes other bytes, for kernel messages only
//! (never for bytes that go back to user space, which are copied raw or
//! [`mangle`]d for /proc text files).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::ops::Deref;

/// An owned file name (a path component, or a whole path where a path is
/// stored: a symlink target, an executable's name)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileName(Box<[u8]>);

impl FileName {
    pub fn new(b: &[u8]) -> Self {
        Self(b.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl Deref for FileName {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for FileName {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for FileName {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for FileName {
    fn from(b: &[u8]) -> Self {
        Self::new(b)
    }
}

impl From<&str> for FileName {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl From<Vec<u8>> for FileName {
    fn from(v: Vec<u8>) -> Self {
        Self(v.into_boxed_slice())
    }
}

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Escaped(&self.0), f)
    }
}

impl fmt::Debug for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

/// A byte string shown as text, invalid UTF-8 as `\xNN` (kernel messages)
pub struct Escaped<'a>(pub &'a [u8]);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for b in chunk.invalid() {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        Ok(())
    }
}

/// `name` is "." or ".."
pub fn is_dot_or_dotdot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// A decimal number as /proc names spell it (Linux name_to_int): digits
/// only, no sign, no leading zero (except "0" itself), no overflow
pub fn name_to_int(name: &[u8]) -> Option<u64> {
    if name.is_empty() || (name.len() > 1 && name[0] == b'0') {
        return None;
    }
    let mut n: u64 = 0;
    for &c in name {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(n)
}

/// Append `b` to `out` with each byte of `esc` written as `\ooo` octal
/// (Linux seq_escape / mangle in fs/proc_namespace.c): /proc text files
/// whose lines must not be forged by a name holding a space or newline
pub fn mangle(out: &mut Vec<u8>, b: &[u8], esc: &[u8]) {
    for &c in b {
        if esc.contains(&c) {
            out.extend_from_slice(&[
                b'\\',
                b'0' + (c >> 6),
                b'0' + ((c >> 3) & 7),
                b'0' + (c & 7),
            ]);
        } else {
            out.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn display_escapes_invalid_utf8() {
        let n = FileName::new(b"a\xffb\xc3\xa9");
        assert_eq!(format!("{}", n), "a\\xffbé");
    }

    #[test]
    fn name_to_int_is_strict() {
        assert_eq!(name_to_int(b"0"), Some(0));
        assert_eq!(name_to_int(b"42"), Some(42));
        assert_eq!(name_to_int(b"042"), None);
        assert_eq!(name_to_int(b"+1"), None);
        assert_eq!(name_to_int(b""), None);
        assert_eq!(name_to_int(b"99999999999999999999999"), None);
    }

    #[test]
    fn mangle_escapes_octal() {
        let mut v = Vec::new();
        mangle(&mut v, b"a b\n\\", b" \t\n\\");
        assert_eq!(v, b"a\\040b\\012\\134");
    }
}

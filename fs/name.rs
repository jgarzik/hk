//! File names as bytes (Linux: a name is any bytes but '/' and NUL;
//! struct qstr, fs/namei.c getname)
//!
//! Names travel through the VFS, the dcache and every filesystem as
//! `&[u8]`; an owned one is a [`FileName`]. Nothing assumes UTF-8:
//! [`FileName`]'s `Display` escapes other bytes, for kernel messages only
//! (never for bytes that go back to user space, which are copied raw or
//! [`mangle`]d for /proc text files).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::ops::Deref;

use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_slice;

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

/// Room for a name inside a dentry (Linux DNAME_INLINE_LEN on 64-bit,
/// its last byte the NUL: names shorter than this stay inline)
pub const DNAME_INLINE_LEN: usize = 40;

/// A dentry's name (Linux struct qstr over d_shortname or an
/// external_name) and its hash: a short name inline, a longer one in a
/// refcounted block allocated, fallibly, before any lock is taken. A
/// copy is a byte copy or a reference: never an allocation, so names
/// are snapshotted (take_dentry_name_snapshot) and moved by a rename
/// (copy_name, swap_names) under spin locks.
#[derive(Clone)]
pub struct DName {
    hash: u64,
    repr: DNameRepr,
}

#[derive(Clone)]
enum DNameRepr {
    /// Linux d_shortname
    Inline {
        len: u8,
        buf: [u8; DNAME_INLINE_LEN],
    },
    /// Linux external_name (its count is the Arc's)
    External(Arc<[u8]>),
}

impl DName {
    /// `b` as a dentry name: ENOMEM if a long one cannot be had (Linux
    /// __d_alloc)
    pub fn new(b: &[u8]) -> Result<Self, KernelError> {
        let repr = match u8::try_from(b.len()) {
            Ok(len) if b.len() < DNAME_INLINE_LEN => {
                let mut buf = [0; DNAME_INLINE_LEN];
                buf[..b.len()].copy_from_slice(b);
                DNameRepr::Inline { len, buf }
            }
            _ => DNameRepr::External(try_arc_slice(b)?),
        };
        Ok(Self {
            hash: name_hash(b),
            repr,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.repr {
            DNameRepr::Inline { len, buf } => &buf[..usize::from(*len)],
            DNameRepr::External(a) => a,
        }
    }

    /// The name's hash (Linux qstr.hash): keyed per boot, unsalted (the
    /// dcache mixes in the parent, so a name moves between parents)
    pub fn hash(&self) -> u64 {
        self.hash
    }
}

impl Default for DName {
    /// The empty name of a root
    fn default() -> Self {
        Self {
            hash: name_hash(b""),
            repr: DNameRepr::Inline {
                len: 0,
                buf: [0; DNAME_INLINE_LEN],
            },
        }
    }
}

/// The dcache's hash key, drawn once per boot from the RNG
#[cfg(not(test))]
static NAME_KEY: spin::Once<[u64; 2]> = spin::Once::new();

#[cfg(not(test))]
fn name_key() -> [u64; 2] {
    *NAME_KEY.call_once(|| {
        let r = || {
            (u64::from(crate::random::get_random_u32()) << 32)
                | u64::from(crate::random::get_random_u32())
        };
        [r(), r()]
    })
}

#[cfg(test)]
fn name_key() -> [u64; 2] {
    [3, 4]
}

/// A name's hash (Linux full_name_hash): SipHash under a per-boot
/// random key, so colliding names cannot be built offline to pile one
/// hash chain up
pub fn name_hash(b: &[u8]) -> u64 {
    crate::util::siphash::siphash_bytes(name_key(), b)
}

/// [`name_hash`] of `b` with ASCII case folded (Linux partial_name_hash
/// over nls_tolower): one hash for names a filesystem matches without
/// case
pub fn name_hash_nocase(b: &[u8]) -> u64 {
    crate::util::siphash::siphash_bytes_map(name_key(), b, |c| c.to_ascii_lowercase())
}

impl Deref for DName {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for DName {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for DName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Equality and order are the bytes' (the hash follows from them), as
/// `Borrow<[u8]>` requires
impl PartialEq for DName {
    fn eq(&self, o: &Self) -> bool {
        self.hash == o.hash && self.as_bytes() == o.as_bytes()
    }
}

impl Eq for DName {}

impl PartialOrd for DName {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for DName {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(o.as_bytes())
    }
}

impl fmt::Display for DName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Escaped(self.as_bytes()), f)
    }
}

impl fmt::Debug for DName {
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

    /// Short names stay inline, long ones are shared: a copy of either
    /// allocates nothing and compares equal
    #[test]
    fn dname_inline_and_external() {
        let s = DName::new(&[b'a'; DNAME_INLINE_LEN - 1]).unwrap();
        assert!(matches!(s.repr, DNameRepr::Inline { .. }));
        let l = DName::new(&[b'b'; DNAME_INLINE_LEN]).unwrap();
        let DNameRepr::External(a) = &l.repr else {
            panic!("long name inline");
        };
        let c = l.clone();
        assert_eq!(Arc::strong_count(a), 2);
        assert!(c == l && c.as_bytes().len() == DNAME_INLINE_LEN);
        assert!(s.as_bytes() == [b'a'; DNAME_INLINE_LEN - 1] && s.hash() != l.hash());
        assert!(DName::default().is_empty());
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

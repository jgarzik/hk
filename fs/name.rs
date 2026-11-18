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

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::sync::rcu::{RcuPuts, RcuReadGuard};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

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

/// A dentry name's inline room in words (Linux DNAME_INLINE_WORDS)
const DNAME_INLINE_WORDS: usize = DNAME_INLINE_LEN / 8;

/// A long name's block (Linux struct external_name): its bytes, never
/// changed, and the deferred puts a dentry's reference goes through
/// when a rename replaces its name ([`DNameSlot`]), so an RCU reader
/// still on it keeps it (Linux copy_name's kfree_rcu)
pub struct ExternalName {
    puts: RcuPuts,
    bytes: Box<[u8]>,
}

crate::rcu_puts!(ExternalName, puts);

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
    External(Arc<ExternalName>),
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
            _ => {
                let mut v = crate::util::kmem::try_vec(b.len(), 0u8)?;
                v.copy_from_slice(b);
                DNameRepr::External(try_arc(ExternalName {
                    puts: RcuPuts::new(),
                    bytes: v.into_boxed_slice(),
                })?)
            }
        };
        Ok(Self {
            hash: name_hash(b),
            repr,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.repr {
            DNameRepr::Inline { len, buf } => &buf[..usize::from(*len)],
            DNameRepr::External(a) => &a.bytes,
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

/// A dentry's name as an RCU walk reads it (Linux d_name over
/// d_shortname / an external_name): the hash, the length, a long
/// name's block and a short name's bytes, each an atomic, so a reader
/// with no lock gets a picture that may be torn by a rename but never
/// reads out of bounds (a short name is copied word by word from its
/// fixed room, a long one read from its own unchanging block); the
/// dentry's `d_seq` tells it to repeat. Changed (`store`) only under
/// the dentry's d_lock held for writing, inside a `d_seq` write
/// section.
///
/// # Invariants
/// `ext` is null for a short name, else an `Arc::into_raw` of an
/// [`ExternalName`] whose reference the slot owns; a reference the
/// slot gave up is dropped no earlier than a grace period after it
/// stopped being published here (`put_rcu`), or with the slot itself,
/// which is dropped only when no reader can reach it (a dentry's free,
/// a grace period after its kill).
pub struct DNameSlot {
    hash: AtomicU64,
    len: AtomicU32,
    ext: AtomicPtr<ExternalName>,
    inline: [AtomicU64; DNAME_INLINE_WORDS],
}

impl DNameSlot {
    pub fn new(n: DName) -> Self {
        let s = Self {
            hash: AtomicU64::new(0),
            len: AtomicU32::new(0),
            ext: AtomicPtr::new(core::ptr::null_mut()),
            inline: [const { AtomicU64::new(0) }; DNAME_INLINE_WORDS],
        };
        s.store(n);
        s
    }

    /// The name's hash (Linux d_name.hash), as of now
    pub fn hash(&self) -> u64 {
        self.hash.load(Ordering::Relaxed)
    }

    /// Become `n` (Linux copy_name), under the dentry's d_lock held for
    /// writing, inside a `d_seq` write section: a long name's block is
    /// shared, never copied, so nothing is allocated; the block it
    /// replaces is let go a grace period from now (Linux kfree_rcu)
    pub fn store(&self, n: DName) {
        let mut buf = [0u8; DNAME_INLINE_LEN];
        let new = match n.repr {
            DNameRepr::Inline { len, buf: b } => {
                buf = b;
                self.len.store(u32::from(len), Ordering::Relaxed);
                core::ptr::null_mut()
            }
            DNameRepr::External(a) => {
                // At most NAME_MAX-ish; a length past u32 cannot be made
                self.len.store(
                    u32::try_from(a.bytes.len()).unwrap_or(u32::MAX),
                    Ordering::Relaxed,
                );
                Arc::into_raw(a).cast_mut()
            }
        };
        self.hash.store(n.hash, Ordering::Relaxed);
        for (w, c) in self.inline.iter().zip(buf.as_chunks::<8>().0) {
            w.store(u64::from_ne_bytes(*c), Ordering::Relaxed);
        }
        // INVARIANT: the new block's reference is the slot's; its bytes
        // are seen by whoever loads the pointer (Release / Acquire)
        let old = self.ext.swap(new, Ordering::AcqRel);
        if let Some(old) = core::ptr::NonNull::new(old) {
            // SAFETY: the slot's own reference (type invariant), given up
            // once here
            let a = unsafe { Arc::from_raw(old.as_ptr()) };
            if crate::sync::rcu::can_queue() {
                crate::sync::rcu::put_rcu(a);
            } else {
                // No other CPU reads: at once
                drop(a);
            }
        }
    }

    /// A long name's block, borrowed for the guard
    fn ext<'g>(&self, _g: &'g RcuReadGuard) -> Option<&'g ExternalName> {
        let p = self.ext.load(Ordering::Acquire);
        // SAFETY: a non-null `ext` held the slot's reference when read
        // under `_g`; that reference is dropped no earlier than a grace
        // period after it stopped being published (type invariant), so
        // after `_g` ends
        unsafe { p.as_ref() }
    }

    /// The short name's room, copied out of its words
    fn inline_copy(&self) -> ([u8; DNAME_INLINE_LEN], usize) {
        let mut buf = [0u8; DNAME_INLINE_LEN];
        for (w, c) in self.inline.iter().zip(buf.as_chunks_mut::<8>().0) {
            *c = w.load(Ordering::Relaxed).to_ne_bytes();
        }
        let len = usize::try_from(self.len.load(Ordering::Relaxed)).unwrap_or(usize::MAX);
        (buf, len.min(DNAME_INLINE_LEN - 1))
    }

    /// `f` on the name's bytes as of now (Linux READ_ONCE of
    /// d_name.name, then its bytes): possibly torn by a concurrent
    /// rename unless the caller holds the dentry's d_lock or a bucket
    /// lock it is in, else checked with `d_seq` after
    pub fn read<R>(&self, g: &RcuReadGuard, f: impl FnOnce(&[u8]) -> R) -> R {
        if let Some(e) = self.ext(g) {
            return f(&e.bytes);
        }
        let (buf, len) = self.inline_copy();
        f(&buf[..len])
    }

    /// A snapshot (Linux take_dentry_name_snapshot's body): a copy of a
    /// short name, a reference to a long one; torn as `read`, so the
    /// caller checks `d_seq`
    pub fn snapshot(&self, g: &RcuReadGuard) -> DName {
        let hash = self.hash();
        let repr = match self.ext(g) {
            Some(e) => {
                let p = core::ptr::from_ref(e);
                // SAFETY: `p` is the slot's `Arc::into_raw`, its count
                // above zero for the guard (type invariant): one more
                DNameRepr::External(unsafe {
                    Arc::increment_strong_count(p);
                    Arc::from_raw(p)
                })
            }
            None => {
                let (buf, len) = self.inline_copy();
                DNameRepr::Inline {
                    // Below DNAME_INLINE_LEN: fits
                    len: len as u8,
                    buf,
                }
            }
        };
        DName { hash, repr }
    }
}

impl Drop for DNameSlot {
    fn drop(&mut self) {
        let p = *self.ext.get_mut();
        // SAFETY: the slot's own reference (type invariant); `&mut`: no
        // reader is left
        drop(core::ptr::NonNull::new(p).map(|p| unsafe { Arc::from_raw(p.as_ptr()) }));
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

    /// A dentry's name slot reads back what it was given, short or long,
    /// shares a long block (one more reference, dropped when replaced;
    /// at once here, with no RCU callbacks), and a snapshot of either
    /// equals the name
    #[test]
    fn slot_store_read_snapshot() {
        let g = crate::sync::rcu::read_lock();
        let long = DName::new(&[b'q'; 70]).unwrap();
        let s = DNameSlot::new(DName::new(b"short").unwrap());
        assert!(s.read(&g, |b| b == b"short"));
        assert!(s.snapshot(&g) == DName::new(b"short").unwrap());
        s.store(long.clone());
        let DNameRepr::External(a) = &long.repr else {
            panic!("long name inline");
        };
        assert_eq!(Arc::strong_count(a), 2);
        assert!(s.read(&g, |b| b == [b'q'; 70]) && s.hash() == long.hash());
        let snap = s.snapshot(&g);
        assert!(snap == long && Arc::strong_count(a) == 3);
        drop(snap);
        s.store(DName::new(b"x").unwrap());
        assert_eq!(Arc::strong_count(a), 1);
        assert!(s.read(&g, |b| b == b"x"));
        // A short name after a long one keeps no stale bytes
        assert!(s.snapshot(&g).as_bytes() == b"x");
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

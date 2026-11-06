//! Plain-old-data byte views (doc/UNSAFE.md rule 2; Linux FromBytes /
//! AsBytes in rust/kernel/transmute.rs)
//!
//! Copying a value between the kernel and bytes (user memory, a disk
//! block, a packet) is sound only for some types:
//! - [`FromBytes`]: every bit pattern is a valid value, so bytes from
//!   outside become one (no `bool`, `char`, enums, references);
//! - [`IntoBytes`]: no padding, so its bytes are all initialized and
//!   copying them out leaks nothing (kernel stack in a `struct stat`).
//!
//! Integers and arrays of them implement both. A `#[repr(C)]` struct gets
//! them from [`pod!`], which checks at compile time that every field is
//! itself plain data and that the fields fill the struct (no padding):
//! a padded ABI struct needs explicit padding fields, as Linux's have.
//! (A type that is only ever read in may implement [`FromBytes`] by hand,
//! with a SAFETY comment, if it must keep implicit padding.)

use core::mem::size_of;

/// Every `size_of::<Self>()` bytes are a valid `Self`
///
/// # Safety
/// Any bit pattern of the type's size is a valid value of it.
pub unsafe trait FromBytes: Copy {
    /// The all-zero value
    #[inline]
    fn zeroed() -> Self {
        // SAFETY: every bit pattern, zero included, is valid (trait)
        unsafe { core::mem::zeroed() }
    }

    /// The value in the first `size_of::<Self>()` bytes of `b` (any
    /// alignment); None if `b` is shorter
    #[inline]
    fn read_from(b: &[u8]) -> Option<Self> {
        if b.len() < size_of::<Self>() {
            return None;
        }
        // SAFETY: `b` holds enough bytes, read unaligned; any bit
        // pattern is valid (trait)
        Some(unsafe { b.as_ptr().cast::<Self>().read_unaligned() })
    }

    /// The value at the start of `b`, borrowed in place: None if `b` is
    /// shorter or misaligned for `Self` (packed headers have alignment 1)
    #[inline]
    fn ref_from(b: &[u8]) -> Option<&Self> {
        if b.len() < size_of::<Self>() || !b.as_ptr().cast::<Self>().is_aligned() {
            return None;
        }
        // SAFETY: in bounds and aligned; any bytes are a valid Self
        // (trait), and plain data has no interior mutability, so shared
        // bytes give a shared value
        Some(unsafe { &*b.as_ptr().cast::<Self>() })
    }
}

/// The value's bytes are all initialized
///
/// # Safety
/// The type has no padding bytes (nor anything else uninitialized).
pub unsafe trait IntoBytes: Copy {
    /// The value's bytes
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the value's own memory, all initialized (trait)
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref::<Self>(self).cast::<u8>(),
                size_of::<Self>(),
            )
        }
    }
}

/// Both: bytes in, bytes out
pub trait Pod: FromBytes + IntoBytes {
    /// The value's bytes, writable: any bytes written leave a valid value
    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the value's own memory, initialized (IntoBytes); any
        // bytes written are a valid value (FromBytes)
        unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut::<Self>(self).cast::<u8>(),
                size_of::<Self>(),
            )
        }
    }
}

impl<T: FromBytes + IntoBytes> Pod for T {}

macro_rules! prim {
    ($($t:ty),*) => {$(
        // SAFETY: an integer: every bit pattern valid, no padding
        unsafe impl FromBytes for $t {}
        // SAFETY: as above
        unsafe impl IntoBytes for $t {}
    )*};
}
prim!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

// SAFETY: elements of a FromBytes type, back to back
unsafe impl<T: FromBytes, const N: usize> FromBytes for [T; N] {}
// SAFETY: an array has no padding between or after elements of a type
// with none (its size is N * size_of::<T>())
unsafe impl<T: IntoBytes, const N: usize> IntoBytes for [T; N] {}

/// The size of the field `f` selects (for [`pod!`]), which must be
/// FromBytes and IntoBytes itself
#[doc(hidden)]
pub const fn pod_field<S, F: Pod>(_f: fn(&S) -> F) -> usize {
    size_of::<F>()
}

/// `pod!(Type { field, ... })`: Type is [`FromBytes`] and [`IntoBytes`].
/// Name every field once (checked); fails to compile if a field is not
/// plain data or the struct has padding.
#[macro_export]
macro_rules! pod {
    ($($t:ident { $($f:ident),* $(,)? });+ $(;)?) => {$(
        const _: () = {
            // Every field, each once (an exhaustive pattern)
            let _ = |x: $t| {
                let $t { $($f: _),* } = x;
            };
            assert!(
                core::mem::size_of::<$t>() == 0 $(+ $crate::util::pod::pod_field(|s: &$t| s.$f))*,
                concat!(stringify!($t), " has padding")
            );
        };
        // SAFETY: every field is FromBytes (pod_field's bound), and they
        // cover the struct (no padding to hold a bad value)
        unsafe impl $crate::util::pod::FromBytes for $t {}
        // SAFETY: every field is IntoBytes and they fill the struct
        // (checked above): no padding
        unsafe impl $crate::util::pod::IntoBytes for $t {}
    )+};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Pair {
        a: u32,
        b: [u16; 2],
    }
    crate::pod!(Pair { a, b });

    #[test]
    fn round_trip() {
        let p = Pair { a: 1, b: [2, 3] };
        let q = Pair::read_from(p.as_bytes()).unwrap();
        assert_eq!(p, q);
        assert!(Pair::read_from(&[0u8; 7]).is_none());
        let mut z = Pair::zeroed();
        z.as_bytes_mut()[0] = 9;
        assert_eq!(z.a, 9);
    }
}

//! Fallible `Box` and `Arc` construction (Rust-for-Linux
//! `KBox::new(x, flags)?`, `Arc::new(x, flags)?`).
//!
//! The global allocator cannot fail gracefully: an allocation it cannot
//! meet panics. Linux returns ENOMEM from every object allocation a
//! syscall makes, so kernel objects are built through these instead of
//! `Box::new`/`Arc::new` (clippy's `disallowed_methods` enforces it):
//!
//! - [`try_box`] allocates fallibly, then hands the block to `Box`.
//! - `*_nofail` are the explicit infallible forms, for boot-time setup
//!   and paths Linux cannot fail either.
//! - [`try_arc`] and [`try_arc_cyclic`] keep std's `Arc` (its `Weak`,
//!   `new_cyclic` and `dyn` coercion are needed and nightly-only to
//!   replicate): the `ArcInner` block is allocated fallibly first and
//!   parked in this CPU's reserve slot, and the allocation `Arc::new`
//!   then makes is served from it (`take_reserved`, called by the
//!   heap). The block's layout is std's `ArcInner<T>`: `#[repr(C)]`
//!   strong and weak counts, then `T`. Should that ever change, the
//!   block is left over and debug builds panic (`boot_selftest` checks
//!   several layouts at boot).
//!
//! Interrupt handlers never take the reserve, and preemption is off
//! while it is set, so the next allocation of that layout on this CPU
//! is `Arc::new`'s. Taking it turns preemption back on: `new_cyclic`
//! allocates before calling its closure, which may then sleep.
//!
//! The heap takes no flags: an allocation is GFP_KERNEL unless the call
//! names another GFP ([`with_gfp`], [`try_box_gfp`], [`try_arc_gfp`];
//! Rust-for-Linux `KBox::new(x, GFP_ATOMIC)`). Only a site where Linux
//! itself allocates GFP_ATOMIC or GFP_NOWAIT in atomic context names
//! one; an unnamed allocation there is listed by lockdep's might_alloc.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::alloc::Layout;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::util::error::KernelError;

/// One CPU's reserved block: its address, size and alignment
struct Reserve {
    ptr: AtomicPtr<u8>,
    size: AtomicUsize,
    align: AtomicUsize,
}

static RESERVE: crate::cpu::PerCpu<Reserve> = crate::percpu!(Reserve {
    ptr: AtomicPtr::new(core::ptr::null_mut()),
    size: AtomicUsize::new(0),
    align: AtomicUsize::new(0),
});

/// This CPU's named heap GFP ([`with_gfp`]): 0 for none, else
/// `NAMED | interrupt depth << 32 | gfp`
static GFP_CX: crate::cpu::PerCpu<core::sync::atomic::AtomicU64> =
    crate::percpu!(core::sync::atomic::AtomicU64::new(0));

/// A [`GFP_CX`] value is set
const NAMED: u64 = 1 << 63;

/// Run `f` with `gfp` named for its heap allocations (Linux passes the
/// GFP to each call: GFP_ATOMIC, GFP_NOWAIT). A GFP that may sleep
/// (RECLAIM) names nothing: that is the default. Otherwise preemption
/// is off for `f` (the section is atomic, as a Linux GFP_ATOMIC caller
/// is), the name is this CPU's, and an interrupt arriving meanwhile does
/// not see it. Scopes nest, the inner one winning. `f` allocates only
/// through fallible calls (`try_*`): an infallible one would panic
/// where the GFP fails.
pub fn with_gfp<R>(gfp: Gfp, f: impl FnOnce() -> R) -> R {
    use crate::arch::{CurrentArch, PerCpuOps};
    if gfp.has(Gfp::RECLAIM) || cfg!(test) || crate::cpu::try_this_id().is_none() {
        return f();
    }
    crate::arch::preempt_disable();
    let cx = GFP_CX.this();
    let depth = u64::from(CurrentArch::interrupt_depth());
    let old = cx.swap(NAMED | depth << 32 | u64::from(gfp.0), Relaxed);
    let r = f();
    cx.store(old, Relaxed);
    crate::arch::preempt_enable();
    r
}

/// The GFP named by a [`with_gfp`] around this allocation, if any
pub fn named_gfp() -> Option<Gfp> {
    use crate::arch::{CurrentArch, PerCpuOps};
    let cx = GFP_CX.get(crate::cpu::try_this_id()?).load(Relaxed);
    let depth = u64::from(CurrentArch::interrupt_depth());
    if cx & NAMED == 0 || (cx >> 32) & 0x7fff_ffff != depth {
        return None;
    }
    Some(Gfp(cx as u32))
}

/// [`try_box`] with `gfp` named (Rust-for-Linux `KBox::new(v, gfp)`)
pub fn try_box_gfp<T>(v: T, gfp: Gfp) -> Result<Box<T>, KernelError> {
    with_gfp(gfp, || try_box(v))
}

/// [`try_arc`] with `gfp` named (Rust-for-Linux `Arc::new(v, gfp)`)
pub fn try_arc_gfp<T>(v: T, gfp: Gfp) -> Result<Arc<T>, KernelError> {
    with_gfp(gfp, || try_arc(v))
}

/// The block std's `Arc::new` allocates for a `T` (`ArcInner<T>`)
pub fn arc_layout<T>() -> Layout {
    let counts = Layout::new::<[AtomicUsize; 2]>();
    let (l, _) = counts
        .extend(Layout::new::<T>())
        .expect("arc_layout: overflow");
    l.pad_to_align()
}

/// `Box::new(v)`, or ENOMEM
pub fn try_box<T>(v: T) -> Result<Box<T>, KernelError> {
    if crate::mm::fault_inject::should_fail() {
        return Err(KernelError::OutOfMemory);
    }
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        // No allocation to fail
        #[expect(clippy::disallowed_methods)]
        return Ok(Box::new(v));
    }
    // SAFETY: a nonzero size
    let p = unsafe { alloc::alloc::alloc(layout) }.cast::<T>();
    if p.is_null() {
        return Err(KernelError::OutOfMemory);
    }
    // SAFETY: `p` is a fresh global-allocator block of `T`'s layout
    unsafe {
        p.write(v);
        Ok(Box::from_raw(p))
    }
}

/// `Arc::new(v)`, or ENOMEM
pub fn try_arc<T>(v: T) -> Result<Arc<T>, KernelError> {
    #[expect(clippy::disallowed_methods)]
    reserved(arc_layout::<T>(), || Arc::new(v))
}

/// `Arc::<[T]>::from(s)`, or ENOMEM (a refcounted copy of a slice:
/// Linux's external_name)
pub fn try_arc_slice<T: Copy>(s: &[T]) -> Result<Arc<[T]>, KernelError> {
    let counts = Layout::new::<[AtomicUsize; 2]>();
    let data = Layout::array::<T>(s.len()).map_err(|_| KernelError::OutOfMemory)?;
    let (l, _) = counts.extend(data).map_err(|_| KernelError::OutOfMemory)?;
    reserved(l.pad_to_align(), || Arc::from(s))
}

/// `Arc::new_cyclic(f)`, or ENOMEM (before `f` runs)
pub fn try_arc_cyclic<T>(f: impl FnOnce(&Weak<T>) -> T) -> Result<Arc<T>, KernelError> {
    #[expect(clippy::disallowed_methods)]
    reserved(arc_layout::<T>(), || Arc::new_cyclic(f))
}

/// `Box::new` where a failure cannot be reported: boot-time setup, or a
/// path Linux cannot fail either (`__GFP_NOFAIL`). Panics on failure; the
/// `_nofail` calls list the kernel's infallible allocations.
#[track_caller]
pub fn box_nofail<T>(v: T) -> Box<T> {
    #[expect(clippy::disallowed_methods)]
    Box::new(v)
}

/// `Arc::new`, infallible: see [`box_nofail`]
#[track_caller]
pub fn arc_nofail<T>(v: T) -> Arc<T> {
    #[expect(clippy::disallowed_methods)]
    Arc::new(v)
}

/// `Arc::new_cyclic`, infallible: see [`box_nofail`]
#[track_caller]
pub fn arc_cyclic_nofail<T>(f: impl FnOnce(&Weak<T>) -> T) -> Arc<T> {
    #[expect(clippy::disallowed_methods)]
    Arc::new_cyclic(f)
}

/// Run `make`, whose first allocation is of `layout`, with a block of it
/// reserved: ENOMEM if the block cannot be had
fn reserved<R>(layout: Layout, make: impl FnOnce() -> R) -> Result<R, KernelError> {
    if crate::mm::fault_inject::should_fail() {
        return Err(KernelError::OutOfMemory);
    }
    // Host tests (std's allocator) and CPUs without per-CPU data yet
    // (early boot) allocate directly
    if cfg!(test) || crate::cpu::try_this_id().is_none() {
        return Ok(make());
    }
    // SAFETY: ArcInner layouts are never zero-sized (the counts)
    let p = unsafe { alloc::alloc::alloc(layout) };
    if p.is_null() {
        return Err(KernelError::OutOfMemory);
    }
    crate::arch::preempt_disable();
    let r = RESERVE.this();
    r.size.store(layout.size(), Relaxed);
    r.align.store(layout.align(), Relaxed);
    r.ptr.store(p, Relaxed);
    let out = make();
    // Still there only if not taken, and then preemption is still off
    // and this is the same CPU. Once taken (preemption on again, maybe
    // another CPU now) `r` may hold another task's block, never ours:
    // ours lives on in the Arc.
    if r.ptr
        .compare_exchange(p, core::ptr::null_mut(), Relaxed, Relaxed)
        .is_ok()
    {
        crate::arch::preempt_enable();
        // SAFETY: our block, untaken
        unsafe { alloc::alloc::dealloc(p, layout) };
        debug_assert!(false, "kalloc: Arc did not allocate ArcInner's layout");
    }
    Ok(out)
}

/// The heap's hook: this CPU's reserved block, if one of `layout` is
/// set and the caller is not an interrupt handler
#[inline]
pub fn take_reserved(layout: Layout) -> Option<*mut u8> {
    use crate::arch::{CurrentArch, PerCpuOps};
    let r = RESERVE.get(crate::cpu::try_this_id()?);
    if r.ptr.load(Relaxed).is_null()
        || CurrentArch::interrupt_depth() > 0
        || r.size.load(Relaxed) != layout.size()
        || r.align.load(Relaxed) != layout.align()
    {
        return None;
    }
    let p = r.ptr.swap(core::ptr::null_mut(), Relaxed);
    // `reserved` turned preemption off when it set the block
    crate::arch::preempt_enable();
    Some(p)
}

/// Boot check that `Arc` takes the reserved block for a few layouts
pub fn selftest() -> bool {
    #[repr(align(64))]
    struct Big([u8; 200]);
    let ok = try_arc(1u8).is_ok()
        && try_arc(7u64).is_ok()
        && try_arc([0u8; 3000]).is_ok()
        && try_arc(Big([0; 200])).is_ok()
        && try_arc_slice(&[7u8; 61]).is_ok_and(|a| a.len() == 61 && a[60] == 7)
        && try_arc_cyclic(|w: &Weak<u32>| w.strong_count() as u32).is_ok()
        // The closure runs preemptible: it may sleep
        && try_arc_cyclic(|_: &Weak<u32>| {
            crate::sync::might_sleep();
            1
        })
        .is_ok();
    // Nothing left over (a leftover panics in debug builds already)
    ok && Big([1; 200]).0[0] == 1 && RESERVE.this().ptr.load(Relaxed).is_null() && gfp_selftest()
}

/// Boot check of named GFPs: nesting, the default, and a named
/// `try_arc` (the reserve taken inside the scope)
fn gfp_selftest() -> bool {
    let outside = named_gfp().is_none();
    let nested = with_gfp(Gfp::NOWAIT, || {
        let a = named_gfp() == Some(Gfp::NOWAIT);
        let b = with_gfp(Gfp::ATOMIC, || named_gfp() == Some(Gfp::ATOMIC));
        let c = with_gfp(Gfp::KERNEL, || named_gfp() == Some(Gfp::NOWAIT));
        a && b && c && named_gfp() == Some(Gfp::NOWAIT)
    });
    let arc = try_arc_gfp(3u32, Gfp::ATOMIC).is_ok_and(|a| *a == 3)
        && try_box_gfp(4u16, Gfp::NOWAIT).is_ok_and(|b| *b == 4);
    outside && nested && arc && named_gfp().is_none() && crate::arch::preempt_count() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_and_arc() {
        assert_eq!(*try_box(5u32).unwrap(), 5);
        assert_eq!(*try_box(()).unwrap(), ());
        let a = try_arc(9u64).unwrap();
        assert_eq!(*a, 9);
        let c = try_arc_cyclic(|w: &Weak<u8>| {
            assert!(w.upgrade().is_none());
            3
        })
        .unwrap();
        assert_eq!(*c, 3);
    }

    #[test]
    fn layout_is_counts_then_value() {
        assert_eq!(
            arc_layout::<u8>().size(),
            2 * core::mem::size_of::<usize>() + 8
        );
        #[repr(align(64))]
        struct A64(u8);
        let l = arc_layout::<A64>();
        assert_eq!((l.size(), l.align()), (128, 64));
    }
}

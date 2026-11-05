//! Scope guards: run cleanup when a scope is left early (Rust-for-Linux
//! `ScopeGuard`, kernel/types.rs).
//!
//! Multi-step setup that must unwind on error builds a guard after each
//! step and calls [`ScopeGuard::dismiss`] once the whole operation has
//! succeeded:
//!
//! ```ignore
//! let a = ScopeGuard::new_with_data(alloc_a()?, free_a);
//! let b = alloc_b()?; // an error here frees `a`
//! publish(a.dismiss(), b);
//! ```

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

/// Runs `cleanup(data)` on drop unless dismissed
#[must_use = "a guard dropped at once runs its cleanup at once"]
pub struct ScopeGuard<T, F: FnOnce(T)> {
    inner: ManuallyDrop<(T, F)>,
}

impl<T, F: FnOnce(T)> ScopeGuard<T, F> {
    /// Guard `data`; `cleanup` gets it back if the guard is dropped armed
    pub fn new_with_data(data: T, cleanup: F) -> Self {
        Self {
            inner: ManuallyDrop::new((data, cleanup)),
        }
    }

    /// Disarm the guard and return the data
    pub fn dismiss(mut self) -> T {
        // SAFETY: `inner` is taken exactly once: `self` is forgotten below,
        // so `drop` never runs
        let (data, _cleanup) = unsafe { ManuallyDrop::take(&mut self.inner) };
        core::mem::forget(self);
        data
    }
}

impl<F: FnOnce(())> ScopeGuard<(), F> {
    /// Guard with no data: `cleanup` runs on drop unless dismissed
    pub fn new(cleanup: F) -> Self {
        Self::new_with_data((), cleanup)
    }
}

impl<T, F: FnOnce(T)> Deref for ScopeGuard<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner.0
    }
}

impl<T, F: FnOnce(T)> DerefMut for ScopeGuard<T, F> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner.0
    }
}

impl<T, F: FnOnce(T)> Drop for ScopeGuard<T, F> {
    fn drop(&mut self) {
        // SAFETY: `dismiss` forgets `self`, so a guard reaching `drop`
        // still owns `inner`
        let (data, cleanup) = unsafe { ManuallyDrop::take(&mut self.inner) };
        cleanup(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn runs_on_drop() {
        let hit = Cell::new(0);
        {
            let _g = ScopeGuard::new(|()| hit.set(hit.get() + 1));
        }
        assert_eq!(hit.get(), 1);
    }

    #[test]
    fn dismiss_skips_cleanup_and_returns_data() {
        let hit = Cell::new(false);
        let g = ScopeGuard::new_with_data(7u32, |_| hit.set(true));
        assert_eq!(g.dismiss(), 7);
        assert!(!hit.get());
    }

    #[test]
    fn cleanup_gets_the_data() {
        let got = Cell::new(0);
        {
            let mut g = ScopeGuard::new_with_data(5u32, |v| got.set(v));
            *g += 1;
        }
        assert_eq!(got.get(), 6);
    }

    #[test]
    fn early_return_unwinds_in_reverse() {
        let log = core::cell::RefCell::new(alloc::vec::Vec::new());
        let setup = |fail: bool| -> Result<(), ()> {
            let a = ScopeGuard::new(|()| log.borrow_mut().push('a'));
            let b = ScopeGuard::new(|()| log.borrow_mut().push('b'));
            if fail {
                return Err(());
            }
            b.dismiss();
            a.dismiss();
            Ok(())
        };
        assert!(setup(false).is_ok());
        assert!(log.borrow().is_empty());
        assert!(setup(true).is_err());
        assert_eq!(*log.borrow(), ['b', 'a']);
    }
}

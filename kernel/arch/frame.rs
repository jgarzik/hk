//! A task's user register frame (Linux struct pt_regs on the kernel stack)
//!
//! Every entry from user mode saves the user registers at the top of the
//! task's kernel stack. That memory has more than one writer: the entry
//! path and everything below it (syscall return value, signal frames,
//! restarts), the task's own syscalls (rt_sigreturn, clone reading it),
//! and a tracer, which writes it while the task sits in a ptrace stop
//! (`task::percpu::task_pt_regs`). A `&mut PtRegs` held across any call
//! that may stop or sleep would let the compiler assume none of those
//! writes happen, so the frame is never borrowed that way: code holds a
//! shared `&Frame` (an `UnsafeCell`, so no `noalias`) and reads or writes
//! a field or a whole copy at a time.
//!
//! The writers never overlap: a tracer writes only while the task is
//! stopped, and the stop's locks order those writes against the task's
//! own accesses.

use core::cell::UnsafeCell;

use super::UserRegs;

/// The user register frame of the current task (`&Frame` is `!Send`:
/// only the task that owns the frame has one)
#[repr(transparent)]
pub struct Frame<T>(UnsafeCell<T>);

impl<T: Clone + UserRegs> Frame<T> {
    /// The frame at `p`
    ///
    /// # Safety
    /// `p` is a task's register frame, valid for `'a`, and only the task
    /// itself (or a tracer while it is stopped) accesses it meanwhile.
    #[inline]
    pub unsafe fn from_ptr<'a>(p: *mut T) -> &'a Frame<T> {
        // SAFETY: repr(transparent) over UnsafeCell<T>, valid per the
        // caller
        unsafe { &*p.cast::<Frame<T>>() }
    }

    /// The frame's address
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    /// Run `f` on the registers
    ///
    /// # Safety
    /// `f` neither sleeps nor stops (no tracer can write the frame while
    /// it runs) nor reaches this frame another way.
    #[inline]
    pub unsafe fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: the caller guarantees no other access while `f` runs
        f(unsafe { &mut *self.0.get() })
    }

    /// A copy of the registers
    #[inline]
    pub fn get(&self) -> T {
        // SAFETY: `clone` neither sleeps nor touches the frame
        unsafe { self.with(|r| r.clone()) }
    }

    /// Replace the registers
    #[inline]
    pub fn set(&self, v: T) {
        // SAFETY: a store
        unsafe { self.with(|r| *r = v) }
    }

    // The UserRegs accessors: each one a load or store of its fields.
    // SAFETY (all): the UserRegs methods neither sleep nor reach the
    // frame another way.

    /// The user PC
    #[inline]
    pub fn ip(&self) -> u64 {
        // SAFETY: see above
        unsafe { self.with(|r| r.ip()) }
    }

    /// The user stack pointer
    #[inline]
    pub fn sp(&self) -> u64 {
        // SAFETY: see above
        unsafe { self.with(|r| r.sp()) }
    }

    #[inline]
    pub fn set_sp(&self, sp: u64) {
        // SAFETY: see above
        unsafe { self.with(|r| r.set_sp(sp)) }
    }

    /// The syscall return register
    #[inline]
    pub fn ret(&self) -> u64 {
        // SAFETY: see above
        unsafe { self.with(|r| r.ret()) }
    }

    #[inline]
    pub fn set_ret(&self, v: u64) {
        // SAFETY: see above
        unsafe { self.with(|r| r.set_ret(v)) }
    }

    /// The frame is a syscall's
    #[inline]
    pub fn in_syscall(&self) -> bool {
        // SAFETY: see above
        unsafe { self.with(|r| r.in_syscall()) }
    }

    /// Its syscall number, u64::MAX if none
    #[inline]
    pub fn syscall_nr(&self) -> u64 {
        // SAFETY: see above
        unsafe { self.with(|r| r.syscall_nr()) }
    }

    /// Its six arguments
    #[inline]
    pub fn syscall_args(&self) -> [u64; 6] {
        // SAFETY: see above
        unsafe { self.with(|r| r.syscall_args()) }
    }

    /// No restart from here on
    #[inline]
    pub fn forget_syscall(&self) {
        // SAFETY: see above
        unsafe { self.with(|r| r.forget_syscall()) }
    }

    /// Re-execute the syscall on return
    #[inline]
    pub fn restart_syscall(&self) {
        // SAFETY: see above
        unsafe { self.with(|r| r.restart_syscall()) }
    }

    /// The recorded arguments become the live ones (after a tracer stop)
    #[inline]
    pub fn sync_syscall_args(&self) {
        // SAFETY: see above
        unsafe { self.with(|r| r.sync_syscall_args()) }
    }
}

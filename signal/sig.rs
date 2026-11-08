//! Signal numbers (Linux include/uapi/asm-generic/signal.h, the same on
//! x86-64 and arm64) and the kernel's classes of them
//! (include/linux/signal.h sig_kernel_*)

use core::num::NonZeroU8;

/// A signal number, 1..=[`NSIG`] (Linux `valid_signal(sig) && sig`)
///
/// The user ABI passes raw numbers; a syscall converts once with
/// [`Signal::new`], where 0 is its own case (a probe, "none" or "the
/// default") and anything past [`NSIG`] its EINVAL.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Signal(NonZeroU8);

/// Number of signals (Linux _NSIG): the highest signal number
pub const NSIG: u32 = 64;

/// `n` as a signal, for the named constants: out of range fails the
/// build (const evaluation)
const fn sig(n: u32) -> Signal {
    match Signal::new(n) {
        Some(s) => s,
        None => panic!("signal number out of range"),
    }
}

impl Signal {
    /// `n` if it is a signal number, 1..=NSIG
    pub const fn new(n: u32) -> Option<Self> {
        if n > NSIG {
            return None;
        }
        // n <= 64 fits a u8
        match NonZeroU8::new(n as u8) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// The number
    #[inline]
    pub const fn nr(self) -> u32 {
        self.0.get() as u32
    }

    /// Its sigset_t bit (Linux sigmask(sig)): bit nr - 1
    #[inline]
    pub const fn bit(self) -> u64 {
        1 << (self.0.get() - 1)
    }

    /// Its slot in a table of NSIG entries (Linux action[sig - 1])
    #[inline]
    pub const fn idx(self) -> usize {
        self.0.get() as usize - 1
    }

    /// A real-time signal: queued once per send, never merged
    pub const fn is_rt(self) -> bool {
        self.nr() >= SIGRTMIN.nr()
    }

    /// Not RT and in `mask` (Linux siginmask)
    const fn in_mask(self, mask: u64) -> bool {
        !self.is_rt() && self.bit() & mask != 0
    }

    /// SIGKILL or SIGSTOP: never caught, blocked or ignored (Linux
    /// sig_kernel_only)
    pub const fn kernel_only(self) -> bool {
        self.in_mask(SIGKILL.bit() | SIGSTOP.bit())
    }

    /// Its default action dumps core (Linux sig_kernel_coredump)
    pub const fn kernel_coredump(self) -> bool {
        const MASK: u64 = SIGQUIT.bit()
            | SIGILL.bit()
            | SIGTRAP.bit()
            | SIGABRT.bit()
            | SIGFPE.bit()
            | SIGSEGV.bit()
            | SIGBUS.bit()
            | SIGSYS.bit()
            | SIGXCPU.bit()
            | SIGXFSZ.bit();
        self.in_mask(MASK)
    }

    /// Its default action ignores it (Linux sig_kernel_ignore; SIGCONT's
    /// continue needs no action while nothing stops)
    pub const fn kernel_ignore(self) -> bool {
        self.in_mask(SIGCONT.bit() | SIGCHLD.bit() | SIGWINCH.bit() | SIGURG.bit())
    }

    /// Its default action stops the task (Linux sig_kernel_stop)
    pub const fn kernel_stop(self) -> bool {
        self.in_mask(SIGSTOP.bit() | SIGTSTP.bit() | SIGTTIN.bit() | SIGTTOU.bit())
    }
}

impl From<Signal> for i32 {
    /// The number as a C int (si_signo, a wait status's low bits)
    fn from(s: Signal) -> i32 {
        i32::from(s.0.get())
    }
}

/// Hangup
pub const SIGHUP: Signal = sig(1);
/// Interrupt (Ctrl+C)
pub const SIGINT: Signal = sig(2);
/// Quit (Ctrl+\)
pub const SIGQUIT: Signal = sig(3);
/// Illegal instruction
pub const SIGILL: Signal = sig(4);
/// Trace/breakpoint trap
pub const SIGTRAP: Signal = sig(5);
/// Abort
pub const SIGABRT: Signal = sig(6);
/// Bus error
pub const SIGBUS: Signal = sig(7);
/// Floating point exception
pub const SIGFPE: Signal = sig(8);
/// Kill (cannot be caught or ignored)
pub const SIGKILL: Signal = sig(9);
/// User-defined signal 1
pub const SIGUSR1: Signal = sig(10);
/// Segmentation fault
pub const SIGSEGV: Signal = sig(11);
/// User-defined signal 2
pub const SIGUSR2: Signal = sig(12);
/// Broken pipe
pub const SIGPIPE: Signal = sig(13);
/// Alarm clock
pub const SIGALRM: Signal = sig(14);
/// Termination
pub const SIGTERM: Signal = sig(15);
/// Stack fault (unused on modern Linux)
pub const SIGSTKFLT: Signal = sig(16);
/// Child stopped or terminated
pub const SIGCHLD: Signal = sig(17);
/// Continue if stopped
pub const SIGCONT: Signal = sig(18);
/// Stop (cannot be caught or ignored)
pub const SIGSTOP: Signal = sig(19);
/// Keyboard stop
pub const SIGTSTP: Signal = sig(20);
/// Background read from tty
pub const SIGTTIN: Signal = sig(21);
/// Background write to tty
pub const SIGTTOU: Signal = sig(22);
/// Urgent condition on socket
pub const SIGURG: Signal = sig(23);
/// CPU time limit exceeded
pub const SIGXCPU: Signal = sig(24);
/// File size limit exceeded
pub const SIGXFSZ: Signal = sig(25);
/// Virtual alarm clock
pub const SIGVTALRM: Signal = sig(26);
/// Profiling timer expired
pub const SIGPROF: Signal = sig(27);
/// Window resize
pub const SIGWINCH: Signal = sig(28);
/// I/O possible
pub const SIGIO: Signal = sig(29);
/// Power failure
pub const SIGPWR: Signal = sig(30);
/// Bad system call
pub const SIGSYS: Signal = sig(31);
/// First real-time signal
pub const SIGRTMIN: Signal = sig(32);
/// Last real-time signal
pub const SIGRTMAX: Signal = sig(NSIG);

#[cfg(test)]
mod tests {
    use super::*;

    /// 1..=NSIG are signals; 0 and past NSIG are not
    #[test]
    fn new_range() {
        assert_eq!(Signal::new(0), None);
        assert_eq!(Signal::new(65), None);
        assert_eq!(Signal::new(u32::MAX), None);
        assert_eq!(Signal::new(256 + 9), None);
        assert_eq!(Signal::new(1).map(Signal::nr), Some(1));
        assert_eq!(Signal::new(64), Some(SIGRTMAX));
        assert_eq!(Signal::new(9), Some(SIGKILL));
    }

    /// The sigset bit and table slot are nr - 1
    #[test]
    fn bit_idx() {
        assert_eq!(SIGHUP.bit(), 1);
        assert_eq!(SIGKILL.bit(), 1 << 8);
        assert_eq!(SIGRTMAX.bit(), 1 << 63);
        assert_eq!(SIGHUP.idx(), 0);
        assert_eq!(SIGRTMAX.idx(), 63);
        assert_eq!(i32::from(SIGCHLD), 17);
    }

    /// Linux's classes: RT signals are in none of them
    #[test]
    fn classes() {
        assert!(SIGKILL.kernel_only() && SIGSTOP.kernel_only());
        assert!(!SIGTERM.kernel_only());
        assert!(SIGSEGV.kernel_coredump() && SIGXFSZ.kernel_coredump());
        assert!(!SIGTERM.kernel_coredump() && !SIGKILL.kernel_coredump());
        assert!(SIGCHLD.kernel_ignore() && SIGCONT.kernel_ignore());
        assert!(SIGURG.kernel_ignore() && SIGWINCH.kernel_ignore());
        assert!(!SIGPIPE.kernel_ignore());
        assert!(SIGTSTP.kernel_stop() && SIGSTOP.kernel_stop());
        assert!(!SIGCONT.kernel_stop());
        assert!(!SIGUSR1.is_rt() && SIGRTMIN.is_rt() && SIGRTMAX.is_rt());
        for rt in [SIGRTMIN, SIGRTMAX] {
            assert!(!rt.kernel_only() && !rt.kernel_coredump());
            assert!(!rt.kernel_ignore() && !rt.kernel_stop());
        }
    }
}

//! Signal information (Linux kernel_siginfo_t, include/linux/signal_types.h)
//! and its user form, the 128-byte asm-generic `siginfo_t` (the same
//! layout on x86-64 and arm64)
//!
//! The union is kept as its bytes, as Linux keeps it: info queued by
//! rt_sigqueueinfo reaches the receiver exactly as sent, whatever its
//! layout. [`SigFields`] is the typed view, chosen by `siginfo_layout`.

use crate::arch::Uaccess;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::util::error::KernelError;
use crate::util::pod::{FromBytes, IntoBytes};

/// siginfo `si_code` values (include/uapi/asm-generic/siginfo.h)
pub mod si_code {
    /// Sent by kill/raise
    pub const SI_USER: i32 = 0;
    /// Sent by the kernel
    pub const SI_KERNEL: i32 = 0x80;
    /// Sent by sigqueue
    pub const SI_QUEUE: i32 = -1;
    /// Sent by timer expiration
    pub const SI_TIMER: i32 = -2;
    /// Sent by a message queue state change
    pub const SI_MESGQ: i32 = -3;
    /// Sent by AIO completion
    pub const SI_ASYNCIO: i32 = -4;
    /// Sent by queued SIGIO
    pub const SI_SIGIO: i32 = -5;
    /// Sent by tkill/tgkill
    pub const SI_TKILL: i32 = -6;
    /// Sent by execve killing subsidiary threads
    pub const SI_DETHREAD: i32 = -7;
    /// Sent by glibc async name lookup completion
    pub const SI_ASYNCNL: i32 = -60;
    /// SIGILL: illegal opcode / illegal operand
    pub const ILL_ILLOPC: i32 = 1;
    pub const ILL_ILLOPN: i32 = 2;
    pub const NSIGILL: i32 = 11;
    /// SIGFPE codes
    pub const FPE_INTDIV: i32 = 1;
    pub const FPE_INTOVF: i32 = 2;
    pub const FPE_FLTDIV: i32 = 3;
    pub const FPE_FLTOVF: i32 = 4;
    pub const FPE_FLTUND: i32 = 5;
    pub const FPE_FLTRES: i32 = 6;
    pub const FPE_FLTINV: i32 = 7;
    pub const NSIGFPE: i32 = 15;
    /// SIGSEGV: address not mapped / no permission for the mapping
    pub const SEGV_MAPERR: i32 = 1;
    pub const SEGV_ACCERR: i32 = 2;
    pub const SEGV_BNDERR: i32 = 3;
    pub const SEGV_PKUERR: i32 = 4;
    pub const NSIGSEGV: i32 = 10;
    /// SIGBUS: invalid alignment / nonexistent physical address
    pub const BUS_ADRALN: i32 = 1;
    pub const BUS_ADRERR: i32 = 2;
    pub const BUS_MCEERR_AR: i32 = 4;
    pub const BUS_MCEERR_AO: i32 = 5;
    pub const NSIGBUS: i32 = 5;
    /// SIGTRAP: breakpoint / trace trap
    pub const TRAP_BRKPT: i32 = 1;
    pub const TRAP_TRACE: i32 = 2;
    pub const TRAP_PERF: i32 = 6;
    pub const NSIGTRAP: i32 = 6;
    /// SIGCHLD codes
    pub const CLD_EXITED: i32 = 1;
    pub const CLD_KILLED: i32 = 2;
    pub const CLD_DUMPED: i32 = 3;
    pub const CLD_TRAPPED: i32 = 4;
    pub const NSIGCHLD: i32 = 6;
    /// SIGPOLL codes
    pub const NSIGPOLL: i32 = 6;
    /// SIGSYS codes
    pub const SYS_SECCOMP: i32 = 1;
    pub const NSIGSYS: i32 = 2;
}

use si_code::*;

/// Size of the union in the kernel form (64-bit __sifields)
const FIELDS: usize = 32;

/// Signal information (Linux kernel_siginfo_t: the first 48 bytes of
/// `siginfo_t`)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    _pad: i32,
    /// union __sifields, as bytes
    f: [u8; FIELDS],
}
crate::pod!(SigInfo {
    signo,
    errno,
    code,
    _pad,
    f
});

/// User `siginfo_t` (asm-generic, 128 bytes): the kernel form, then
/// zeroes (Linux SI_EXPANSION_SIZE)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserSigInfo {
    k: SigInfo,
    _expansion: [u8; EXPANSION],
}
crate::pod!(UserSigInfo { k, _expansion });

/// Linux SI_EXPANSION_SIZE
const EXPANSION: usize = 128 - core::mem::size_of::<SigInfo>();

const _: () = assert!(core::mem::size_of::<SigInfo>() == 48);
const _: () = assert!(core::mem::size_of::<UserSigInfo>() == 128);

/// Which member of the union a siginfo carries (Linux enum
/// siginfo_layout)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Kill,
    Timer,
    Poll,
    Fault,
    FaultMceerr,
    FaultBnderr,
    FaultPkuerr,
    FaultPerf,
    Chld,
    Rt,
    Sys,
}

/// The typed union (Linux union __sifields)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigFields {
    /// kill, tkill (SI_USER, SI_TKILL) and kernel sends: sender
    Kill { pid: i32, uid: u32 },
    /// sigqueue and other queued senders: sender and sigval_t
    Rt { pid: i32, uid: u32, value: u64 },
    /// POSIX timers: timer id, overrun count, sigval_t
    Timer { tid: i32, overrun: i32, value: u64 },
    /// SIGCHLD: the child, its status and CPU times (clock ticks)
    Chld {
        pid: i32,
        uid: u32,
        status: i32,
        utime: i64,
        stime: i64,
    },
    /// Faults: the address and its least significant bit (MCEERR)
    Fault { addr: u64, addr_lsb: i16 },
    /// SIGSYS: calling instruction, syscall number, AUDIT_ARCH_*
    Sys {
        call_addr: u64,
        syscall: i32,
        arch: u32,
    },
    /// SIGPOLL: band event and fd
    Poll { band: i64, fd: i32 },
}

/// Linux sig_sicodes: the signals whose positive codes are their own,
/// with the highest code and its layout
fn sig_sicodes(sig: u32) -> Option<(i32, Layout)> {
    use super::{SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGIO, SIGSEGV, SIGSYS, SIGTRAP};
    Some(match sig {
        SIGILL => (NSIGILL, Layout::Fault),
        SIGFPE => (NSIGFPE, Layout::Fault),
        SIGSEGV => (NSIGSEGV, Layout::Fault),
        SIGBUS => (NSIGBUS, Layout::Fault),
        SIGTRAP => (NSIGTRAP, Layout::Fault),
        SIGCHLD => (NSIGCHLD, Layout::Chld),
        SIGIO => (NSIGPOLL, Layout::Poll),
        SIGSYS => (NSIGSYS, Layout::Sys),
        _ => return None,
    })
}

/// `sig` has positive codes of its own (Linux sig_specific_sicodes)
pub fn specific_codes(sig: u32) -> bool {
    sig_sicodes(sig).is_some()
}

/// The union member `sig` with `code` carries (Linux siginfo_layout)
pub fn layout(sig: u32, code: i32) -> Layout {
    use super::{SIGBUS, SIGSEGV, SIGTRAP};
    if code > SI_USER && code < SI_KERNEL {
        match sig_sicodes(sig) {
            Some((limit, l)) if code <= limit => match (sig, code) {
                (SIGBUS, BUS_MCEERR_AR..=BUS_MCEERR_AO) => Layout::FaultMceerr,
                (SIGSEGV, SEGV_BNDERR) => Layout::FaultBnderr,
                (SIGSEGV, SEGV_PKUERR) => Layout::FaultPkuerr,
                (SIGTRAP, TRAP_PERF) => Layout::FaultPerf,
                _ => l,
            },
            _ if code <= NSIGPOLL => Layout::Poll,
            _ => Layout::Kill,
        }
    } else if code == SI_TIMER {
        Layout::Timer
    } else if code == SI_SIGIO {
        Layout::Poll
    } else if code < 0 {
        Layout::Rt
    } else {
        Layout::Kill
    }
}

/// Linux known_siginfo_layout: a code whose fields fit the kernel form
fn known_layout(sig: u32, code: i32) -> bool {
    if code == SI_KERNEL {
        true
    } else if code > SI_USER {
        match sig_sicodes(sig) {
            Some((limit, _)) => code <= limit,
            None => code <= NSIGPOLL,
        }
    } else {
        code >= SI_DETHREAD || code == SI_ASYNCNL
    }
}

impl SigInfo {
    /// Info for `sig` with `code` and the union member `fields` (the rest
    /// zero, Linux clear_siginfo)
    pub fn new(sig: u32, code: i32, fields: SigFields) -> Self {
        let mut s = Self {
            signo: sig as i32,
            code,
            ..Self::default()
        };
        s.set_fields(fields);
        s
    }

    /// SI_USER or SI_TKILL info from sender `pid`, `uid`
    pub fn kill(sig: u32, code: i32, pid: i32, uid: u32) -> Self {
        Self::new(sig, code, SigFields::Kill { pid, uid })
    }

    /// A fault at `addr` (Linux force_sig_fault)
    pub fn fault(sig: u32, code: i32, addr: u64) -> Self {
        Self::new(sig, code, SigFields::Fault { addr, addr_lsb: 0 })
    }

    /// The signal number
    pub fn sig(&self) -> u32 {
        self.signo as u32
    }

    /// The union member this info carries
    pub fn layout(&self) -> Layout {
        layout(self.sig(), self.code)
    }

    /// The typed union
    pub fn fields(&self) -> SigFields {
        match self.layout() {
            Layout::Kill => SigFields::Kill {
                pid: self.i32_at(0),
                uid: self.u32_at(4),
            },
            Layout::Rt => SigFields::Rt {
                pid: self.i32_at(0),
                uid: self.u32_at(4),
                value: self.u64_at(8),
            },
            Layout::Timer => SigFields::Timer {
                tid: self.i32_at(0),
                overrun: self.i32_at(4),
                value: self.u64_at(8),
            },
            Layout::Chld => SigFields::Chld {
                pid: self.i32_at(0),
                uid: self.u32_at(4),
                status: self.i32_at(8),
                utime: self.u64_at(16) as i64,
                stime: self.u64_at(24) as i64,
            },
            Layout::Fault
            | Layout::FaultMceerr
            | Layout::FaultBnderr
            | Layout::FaultPkuerr
            | Layout::FaultPerf => SigFields::Fault {
                addr: self.u64_at(0),
                addr_lsb: i16::from_ne_bytes([self.f[8], self.f[9]]),
            },
            Layout::Sys => SigFields::Sys {
                call_addr: self.u64_at(0),
                syscall: self.i32_at(8),
                arch: self.u32_at(12),
            },
            Layout::Poll => SigFields::Poll {
                band: self.u64_at(0) as i64,
                fd: self.i32_at(8),
            },
        }
    }

    fn set_fields(&mut self, fields: SigFields) {
        self.f = [0; FIELDS];
        match fields {
            SigFields::Kill { pid, uid } => {
                self.put(0, &pid.to_ne_bytes());
                self.put(4, &uid.to_ne_bytes());
            }
            SigFields::Rt { pid, uid, value } => {
                self.put(0, &pid.to_ne_bytes());
                self.put(4, &uid.to_ne_bytes());
                self.put(8, &value.to_ne_bytes());
            }
            SigFields::Timer {
                tid,
                overrun,
                value,
            } => {
                self.put(0, &tid.to_ne_bytes());
                self.put(4, &overrun.to_ne_bytes());
                self.put(8, &value.to_ne_bytes());
            }
            SigFields::Chld {
                pid,
                uid,
                status,
                utime,
                stime,
            } => {
                self.put(0, &pid.to_ne_bytes());
                self.put(4, &uid.to_ne_bytes());
                self.put(8, &status.to_ne_bytes());
                self.put(16, &utime.to_ne_bytes());
                self.put(24, &stime.to_ne_bytes());
            }
            SigFields::Fault { addr, addr_lsb } => {
                self.put(0, &addr.to_ne_bytes());
                self.put(8, &addr_lsb.to_ne_bytes());
            }
            SigFields::Sys {
                call_addr,
                syscall,
                arch,
            } => {
                self.put(0, &call_addr.to_ne_bytes());
                self.put(8, &syscall.to_ne_bytes());
                self.put(12, &arch.to_ne_bytes());
            }
            SigFields::Poll { band, fd } => {
                self.put(0, &band.to_ne_bytes());
                self.put(8, &fd.to_ne_bytes());
            }
        }
    }

    fn put(&mut self, at: usize, b: &[u8]) {
        self.f[at..at + b.len()].copy_from_slice(b);
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_ne_bytes([self.f[at], self.f[at + 1], self.f[at + 2], self.f[at + 3]])
    }

    fn i32_at(&self, at: usize) -> i32 {
        self.u32_at(at) as i32
    }

    fn u64_at(&self, at: usize) -> u64 {
        u64::from(self.u32_at(at)) | u64::from(self.u32_at(at + 4)) << 32
    }

    /// The user form: this, then zeroes
    pub fn to_user(&self) -> UserSigInfo {
        UserSigInfo {
            k: *self,
            _expansion: [0; EXPANSION],
        }
    }

    /// Write the user `siginfo_t` at `to` (Linux copy_siginfo_to_user)
    pub fn copy_to_user(&self, to: u64) -> Result<(), KernelError> {
        copy_to_user::<Uaccess>(to, self.to_user().as_bytes())
            .map(|_| ())
            .map_err(|_| KernelError::BadAddress)
    }

    /// Read a user `siginfo_t` at `from` (Linux copy_siginfo_from_user):
    /// the kernel form as is; for a code of no known layout its other
    /// bytes must be zero (E2BIG), so it can be given back exactly
    pub fn copy_from_user(from: u64) -> Result<Self, KernelError> {
        let mut u = [0u8; 128];
        let k = core::mem::size_of::<SigInfo>();
        copy_from_user::<Uaccess>(&mut u[..k], from, k).map_err(|_| KernelError::BadAddress)?;
        let mut s = <Self as FromBytes>::read_from(&u[..k]).ok_or(KernelError::BadAddress)?;
        s._pad = 0;
        if !known_layout(s.sig(), s.code) {
            let rest = from.checked_add(k as u64).ok_or(KernelError::BadAddress)?;
            copy_from_user::<Uaccess>(&mut u[k..], rest, EXPANSION)
                .map_err(|_| KernelError::BadAddress)?;
            if u[k..].iter().any(|&b| b != 0) {
                return Err(KernelError::ArgListTooLong);
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SIGCHLD, SIGRTMIN, SIGSEGV, SIGUSR1};

    /// Each union member reads back as written, at the asm-generic
    /// offsets (si_pid 16, si_uid 20, si_value/si_status 24, si_utime 32)
    #[test]
    fn fields_round_trip() {
        let rt = SigInfo::new(
            SIGRTMIN + 1,
            SI_QUEUE,
            SigFields::Rt {
                pid: 7,
                uid: 8,
                value: 0x1122_3344_5566_7788,
            },
        );
        assert_eq!(rt.layout(), Layout::Rt);
        let b = rt.to_user();
        let b = b.as_bytes();
        assert_eq!(b[16], 7);
        assert_eq!(b[20], 8);
        assert_eq!(b[24], 0x88);
        let ch = SigFields::Chld {
            pid: 1,
            uid: 2,
            status: 3,
            utime: 4,
            stime: 5,
        };
        let c = SigInfo::new(SIGCHLD, CLD_EXITED, ch);
        assert_eq!(c.fields(), ch);
        assert_eq!(c.to_user().as_bytes()[32], 4);
        let f = SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0xdead_beef_0000);
        assert_eq!(
            f.fields(),
            SigFields::Fault {
                addr: 0xdead_beef_0000,
                addr_lsb: 0
            }
        );
    }

    /// Linux siginfo_layout's choices
    #[test]
    fn layouts() {
        assert_eq!(layout(SIGUSR1, SI_USER), Layout::Kill);
        assert_eq!(layout(SIGUSR1, SI_TKILL), Layout::Rt);
        assert_eq!(layout(SIGUSR1, SI_TIMER), Layout::Timer);
        assert_eq!(layout(SIGUSR1, SI_KERNEL), Layout::Kill);
        assert_eq!(layout(SIGUSR1, 3), Layout::Poll);
        assert_eq!(layout(SIGUSR1, 7), Layout::Kill);
        assert_eq!(layout(SIGSEGV, SEGV_PKUERR), Layout::FaultPkuerr);
        assert_eq!(layout(SIGCHLD, CLD_EXITED), Layout::Chld);
        assert!(known_layout(SIGUSR1, SI_QUEUE));
        assert!(!known_layout(SIGUSR1, -8));
        assert!(!known_layout(SIGUSR1, 7));
    }
}

//! Architecture-specific tests (some x86-64 only)

#[cfg(target_arch = "x86_64")]
pub mod arch_gs;
pub mod fpu;
#[cfg(target_arch = "x86_64")]
pub mod gs_sel;
#[cfg(target_arch = "x86_64")]
pub mod ioport;
pub mod tls;

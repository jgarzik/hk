//! eBPF (extended Berkeley Packet Filter) subsystem
//!
//! This module provides the eBPF virtual machine used for seccomp filters,
//! packet filtering, and other programmable kernel extensions.
//!
//! ## Architecture
//!
//! eBPF programs execute in a sandboxed virtual machine with:
//! - 11 64-bit registers (R0-R10)
//! - 512-byte stack
//! - Context pointer passed in R1
//! - Return value in R0
//!
//! ## cBPF Compatibility
//!
//! For seccomp(2) compatibility, classic BPF (cBPF) programs using
//! sock_filter format are converted to eBPF before execution.

mod convert;
mod insn;
mod interp;
mod prog;

pub use convert::{SockFilter, cbpf_to_ebpf, validate_cbpf};
pub use insn::*;
pub use interp::bpf_run;
pub use prog::BpfProg;

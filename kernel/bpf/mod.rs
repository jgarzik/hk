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
//! ## Syscall Interface
//!
//! The bpf() syscall provides userspace access to:
//! - BPF maps (key-value stores): hash tables, arrays
//! - BPF programs: loaded and verified before execution
//!
//! ## cBPF Compatibility
//!
//! For seccomp(2) compatibility, classic BPF (cBPF) programs using
//! sock_filter format are converted to eBPF before execution.

mod convert;
mod fd;
mod insn;
mod interp;
mod map;
mod prog;
pub mod syscall;
mod verifier;

pub use convert::{SockFilter, cbpf_to_ebpf, validate_cbpf};
pub use fd::{create_bpf_map_fd, create_bpf_prog_fd, get_bpf_map_from_fd, get_bpf_prog_from_fd};
pub use insn::*;
pub use interp::bpf_run;
pub use map::{BpfMap, BpfMapOps, create_map};
pub use prog::BpfProg;
pub use syscall::sys_bpf;
pub use verifier::verify_bpf_prog;

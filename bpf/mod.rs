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
//! ## Classic BPF
//!
//! `classic` checks and runs classic (sock_filter) programs, for
//! socket filters and seccomp(2).

pub mod classic;
pub mod convert;
mod fd;
mod insn;
pub mod interp;
mod map;
mod prog;
pub mod syscall;
pub mod verifier;

pub use fd::{create_bpf_map_fd, create_bpf_prog_fd, get_bpf_map_from_fd, get_bpf_prog_from_fd};
pub use insn::*;
pub use map::{BpfMap, BpfMapOps, create_map};
pub use prog::BpfProg;
pub use syscall::sys_bpf;

#[cfg(test)]
mod tests;

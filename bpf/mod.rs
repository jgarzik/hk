//! BPF: hk's one in-kernel program engine
//!
//! - `interp`: the RFC 9669 eBPF interpreter, every access checked
//!   against its region (context, stack)
//! - `verifier`: iterative checks of shape, forward-only control flow
//!   and register/stack types before a program may run
//! - `classic`: classic (sock_filter) programs: Linux's checker, and the
//!   classic interpreter the converter is tested against
//! - `convert`: Linux's classic-to-eBPF conversion; seccomp(2) and
//!   SO_ATTACH_FILTER run their programs this way
//! - `syscall`, `map`, `prog`, `fd`: bpf(2) maps and program loading
//!   (nothing attaches a loaded program yet: doc/ROADMAP.md phase E)

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

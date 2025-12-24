//! Linux syscall wrappers for hk kernel testing
//!
//! This crate provides a common interface for Linux syscalls across different
//! architectures (x86_64 and aarch64). Each architecture has different syscall
//! numbers and calling conventions.
//!
//! # Architecture Differences
//!
//! | Aspect | x86_64 | aarch64 |
//! |--------|--------|---------|
//! | Instruction | `syscall` | `svc #0` |
//! | Syscall Number | RAX | X8 |
//! | Arguments | RDI, RSI, RDX, R10, R8, R9 | X0-X5 |
//! | Return Value | RAX | X0 |
//!
//! Additionally, aarch64 uses different syscall numbers and has removed some
//! legacy syscalls (open, fork, dup2) in favor of newer alternatives (openat,
//! clone, dup3).

#![no_std]

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

mod types;
pub use types::*;

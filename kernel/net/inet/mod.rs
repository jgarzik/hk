//! IPv4 configuration: interface addresses, FIB and routing
//!
//! Family-specific; IPv6 gets a sibling `inet6` with the same shape
//! (per-device address list, per-namespace FIB, input/output routing).

pub mod fib;
pub mod frag;
pub mod ifaddr;
pub mod port;
pub mod route;

//! Routing Table
//!
//! This module implements a simple IPv4 routing table for
//! next-hop determination.
//!
//! Routes are stored per-namespace in NetNamespace.

use alloc::sync::Arc;

use crate::net::device::NetDevice;
use crate::net::ipv4::Ipv4Addr;

/// Route entry
#[derive(Clone)]
pub struct Route {
    /// Destination network
    pub dest: Ipv4Addr,
    /// Network mask
    pub netmask: Ipv4Addr,
    /// Gateway (0.0.0.0 for directly connected)
    pub gateway: Ipv4Addr,
    /// Output interface
    pub dev: Arc<NetDevice>,
    /// Route flags
    pub flags: u32,
    /// Metric (lower is better)
    pub metric: u32,
}

/// Route flags
pub mod flags {
    /// Route is up
    pub const RTF_UP: u32 = 0x0001;
    /// Destination is a gateway
    pub const RTF_GATEWAY: u32 = 0x0002;
    /// Destination is a host
    pub const RTF_HOST: u32 = 0x0004;
    /// Route is dynamic
    pub const RTF_DYNAMIC: u32 = 0x0010;
    /// Route is default
    pub const RTF_DEFAULT: u32 = 0x10000;
}

impl Route {
    /// Check if this route matches a destination
    pub fn matches(&self, dest: Ipv4Addr) -> bool {
        (dest & self.netmask) == (self.dest & self.netmask)
    }

    /// Check if destination is through a gateway
    pub fn is_gateway(&self) -> bool {
        !self.gateway.is_unspecified()
    }

    /// Get the number of bits in the prefix (for longest-prefix matching)
    pub fn prefix_len(&self) -> u32 {
        self.netmask.to_u32().count_ones()
    }
}

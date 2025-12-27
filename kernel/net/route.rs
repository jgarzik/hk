//! Routing Table
//!
//! This module implements a simple IPv4 routing table for
//! next-hop determination.
//!
//! Routes are stored per-namespace in NetNamespace.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::net::KernelError;
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

/// Initialize routing
pub fn init() {
    // Nothing to do - routes are added when interfaces come up
    // Routes are per-namespace and stored in NetNamespace
}

/// Add a route for a directly connected interface in current namespace
pub fn add_interface_route(dest: Ipv4Addr, netmask: Ipv4Addr, dev: Arc<NetDevice>) {
    crate::net::current_net_ns().add_interface_route(dest, netmask, dev);
}

/// Add a default route (gateway) in current namespace
pub fn add_default_route(gateway: Ipv4Addr, dev: Arc<NetDevice>) {
    crate::net::current_net_ns().add_default_route(gateway, dev);
}

/// Add a host route in current namespace
pub fn add_host_route(dest: Ipv4Addr, gateway: Ipv4Addr, dev: Arc<NetDevice>) {
    let route = Route {
        dest,
        netmask: Ipv4Addr::new(255, 255, 255, 255),
        gateway,
        dev,
        flags: flags::RTF_UP
            | flags::RTF_HOST
            | if !gateway.is_unspecified() {
                flags::RTF_GATEWAY
            } else {
                0
            },
        metric: 0,
    };

    crate::net::current_net_ns().add_route(route);
}

/// Look up a route for a destination address in current namespace
///
/// Returns the output device and next-hop address.
/// Uses longest-prefix matching for route selection.
pub fn route_lookup(dest: Ipv4Addr) -> Result<(Arc<NetDevice>, Ipv4Addr), KernelError> {
    crate::net::current_net_ns().route_lookup(dest)
}

/// Get all routes in current namespace (for debugging)
pub fn get_routes() -> Vec<Route> {
    crate::net::current_net_ns().routes.read().clone()
}

/// Clear all routes in current namespace
pub fn clear_routes() {
    crate::net::current_net_ns().routes.write().clear();
}

//! NUMA (Non-Uniform Memory Access) Topology Support
//!
//! This module provides core NUMA data structures and topology discovery
//! for multi-socket systems. On x86-64, topology is discovered from ACPI
//! SRAT/SLIT tables. On aarch64, it comes from device tree numa-node-id
//! properties.
//!
//! Single-socket systems (or systems without NUMA tables) are represented
//! as having a single NUMA node (node 0) containing all CPUs and memory.

use crate::arch::IrqSpinlock;

/// Maximum number of NUMA nodes supported
pub const MAX_NUMA_NODES: usize = 64;

/// Maximum number of CPUs supported for NUMA mapping
pub const MAX_CPUS: usize = 256;

/// Distance value for same-node access (local)
pub const LOCAL_DISTANCE: u8 = 10;

/// Default distance value for different-node access (remote)
pub const REMOTE_DISTANCE: u8 = 20;

/// Maximum valid distance value
pub const MAX_DISTANCE: u8 = 255;

/// Represents a NUMA node with its memory range and associated CPUs
#[derive(Clone, Copy, Debug)]
pub struct NumaNode {
    /// Node identifier (0-based)
    pub node_id: u32,
    /// Starting page frame number for this node's memory
    pub start_pfn: u64,
    /// Ending page frame number (exclusive) for this node's memory
    pub end_pfn: u64,
    /// Total number of present pages on this node
    pub present_pages: u64,
    /// Bitmask of CPUs belonging to this node (supports up to 64 CPUs per node)
    pub cpu_mask: u64,
}

impl NumaNode {
    /// Create a new NUMA node
    pub const fn new(node_id: u32) -> Self {
        Self {
            node_id,
            start_pfn: 0,
            end_pfn: 0,
            present_pages: 0,
            cpu_mask: 0,
        }
    }

    /// Check if a CPU belongs to this node
    pub fn has_cpu(&self, cpu_id: u32) -> bool {
        if cpu_id >= 64 {
            return false;
        }
        (self.cpu_mask & (1u64 << cpu_id)) != 0
    }

    /// Add a CPU to this node
    pub fn add_cpu(&mut self, cpu_id: u32) {
        if cpu_id < 64 {
            self.cpu_mask |= 1u64 << cpu_id;
        }
    }

    /// Get the size of memory on this node in bytes
    pub fn memory_size(&self) -> u64 {
        self.present_pages * 4096 // PAGE_SIZE
    }
}

/// System-wide NUMA topology information
pub struct NumaTopology {
    /// Number of online NUMA nodes
    pub nr_nodes: usize,
    /// Per-node information (None if node not present)
    pub nodes: [Option<NumaNode>; MAX_NUMA_NODES],
    /// CPU to node mapping
    pub cpu_to_node: [u8; MAX_CPUS],
    /// Distance matrix between nodes (node_distance[from][to])
    pub distance: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// Bitmask of online nodes
    pub node_online_mask: u64,
    /// Whether topology has been initialized
    pub initialized: bool,
}

impl Default for NumaTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaTopology {
    /// Create a new uninitialized NUMA topology
    pub const fn new() -> Self {
        Self {
            nr_nodes: 0,
            nodes: [None; MAX_NUMA_NODES],
            cpu_to_node: [0; MAX_CPUS],
            distance: [[0; MAX_NUMA_NODES]; MAX_NUMA_NODES],
            node_online_mask: 0,
            initialized: false,
        }
    }

    /// Initialize with a single-node fallback topology
    ///
    /// Used when no NUMA information is available (single-socket systems
    /// or systems without SRAT/device-tree NUMA properties).
    pub fn init_single_node(&mut self, total_pages: u64, nr_cpus: usize) {
        let mut node = NumaNode::new(0);
        node.start_pfn = 0;
        node.end_pfn = total_pages;
        node.present_pages = total_pages;

        // Assign all CPUs to node 0
        for cpu in 0..nr_cpus.min(64) {
            node.add_cpu(cpu as u32);
            self.cpu_to_node[cpu] = 0;
        }

        self.nodes[0] = Some(node);
        self.nr_nodes = 1;
        self.node_online_mask = 1;

        // Set up distance matrix (single node = all local)
        self.distance[0][0] = LOCAL_DISTANCE;

        self.initialized = true;
    }

    /// Add a NUMA node to the topology
    pub fn add_node(&mut self, node: NumaNode) {
        let node_id = node.node_id as usize;
        if node_id >= MAX_NUMA_NODES {
            return;
        }

        // Update CPU-to-node mapping based on node's cpu_mask
        for cpu in 0..64u32 {
            if node.has_cpu(cpu) && (cpu as usize) < MAX_CPUS {
                self.cpu_to_node[cpu as usize] = node_id as u8;
            }
        }

        self.nodes[node_id] = Some(node);
        self.node_online_mask |= 1u64 << node_id;

        // Recalculate node count
        self.nr_nodes = self.node_online_mask.count_ones() as usize;
    }

    /// Set the distance between two nodes
    pub fn set_distance(&mut self, from: usize, to: usize, dist: u8) {
        if from < MAX_NUMA_NODES && to < MAX_NUMA_NODES {
            self.distance[from][to] = dist;
        }
    }

    /// Initialize default distances (LOCAL for same node, REMOTE for different)
    pub fn init_default_distances(&mut self) {
        for from in 0..MAX_NUMA_NODES {
            for to in 0..MAX_NUMA_NODES {
                if from == to {
                    self.distance[from][to] = LOCAL_DISTANCE;
                } else {
                    self.distance[from][to] = REMOTE_DISTANCE;
                }
            }
        }
    }

    /// Get the NUMA node for a given CPU
    pub fn cpu_to_node(&self, cpu: u32) -> u32 {
        if (cpu as usize) < MAX_CPUS {
            self.cpu_to_node[cpu as usize] as u32
        } else {
            0 // Default to node 0
        }
    }

    /// Get the distance between two nodes
    pub fn node_distance(&self, from: u32, to: u32) -> u8 {
        let from = from as usize;
        let to = to as usize;
        if from < MAX_NUMA_NODES && to < MAX_NUMA_NODES {
            let dist = self.distance[from][to];
            if dist == 0 {
                // Not initialized, return default
                if from == to {
                    LOCAL_DISTANCE
                } else {
                    REMOTE_DISTANCE
                }
            } else {
                dist
            }
        } else {
            MAX_DISTANCE
        }
    }

    /// Check if a node is online
    pub fn node_online(&self, node: u32) -> bool {
        if node >= 64 {
            return false;
        }
        (self.node_online_mask & (1u64 << node)) != 0
    }

    /// Get the number of online nodes
    pub fn num_nodes(&self) -> usize {
        self.nr_nodes
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: u32) -> Option<&NumaNode> {
        if (node_id as usize) < MAX_NUMA_NODES {
            self.nodes[node_id as usize].as_ref()
        } else {
            None
        }
    }

    /// Get the online node mask
    pub fn online_mask(&self) -> u64 {
        self.node_online_mask
    }

    /// Assign a CPU to a specific node
    pub fn assign_cpu_to_node(&mut self, cpu: u32, node: u32) {
        if (cpu as usize) < MAX_CPUS && (node as usize) < MAX_NUMA_NODES {
            self.cpu_to_node[cpu as usize] = node as u8;

            // Also update the node's cpu_mask if node exists
            if let Some(ref mut numa_node) = self.nodes[node as usize] {
                numa_node.add_cpu(cpu);
            }
        }
    }

    /// Mark topology as initialized
    pub fn set_initialized(&mut self) {
        self.initialized = true;
    }

    /// Check if topology has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

/// Global NUMA topology singleton
///
/// Protected by IrqSpinlock to allow access from interrupt context
/// (e.g., page fault handlers querying CPU-to-node mapping).
pub static NUMA_TOPOLOGY: IrqSpinlock<NumaTopology> = IrqSpinlock::new(NumaTopology::new());

/// Initialize NUMA topology as single-node fallback
///
/// Called when no SRAT table (x86-64) or numa-node-id properties (aarch64)
/// are found. Creates a synthetic node 0 containing all memory and CPUs.
pub fn init_single_node_fallback(total_pages: u64, nr_cpus: usize) {
    let mut topology = NUMA_TOPOLOGY.lock();
    if !topology.is_initialized() {
        topology.init_default_distances();
        topology.init_single_node(total_pages, nr_cpus);
        crate::printkln!(
            "NUMA: 1 node (fallback), {} MB, {} CPUs",
            total_pages * 4 / 1024,
            nr_cpus
        );
    }
}

/// Print NUMA topology summary to console
pub fn print_topology() {
    let topology = NUMA_TOPOLOGY.lock();
    if !topology.is_initialized() {
        crate::printkln!("NUMA: not initialized");
        return;
    }

    crate::printkln!("NUMA: {} node(s) online", topology.nr_nodes);
    for node_id in 0..MAX_NUMA_NODES {
        if let Some(node) = &topology.nodes[node_id] {
            let mb = node.memory_size() / (1024 * 1024);
            let cpus = node.cpu_mask.count_ones();
            crate::printkln!(
                "  node {}: {} MB, {} CPUs (mask: {:#x})",
                node_id,
                mb,
                cpus,
                node.cpu_mask
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_node_init() {
        let mut topology = NumaTopology::new();
        topology.init_default_distances();
        topology.init_single_node(1024, 4); // 4MB, 4 CPUs

        assert_eq!(topology.nr_nodes, 1);
        assert!(topology.node_online(0));
        assert!(!topology.node_online(1));
        assert_eq!(topology.cpu_to_node(0), 0);
        assert_eq!(topology.cpu_to_node(3), 0);
        assert_eq!(topology.node_distance(0, 0), LOCAL_DISTANCE);
    }

    #[test]
    fn test_multi_node() {
        let mut topology = NumaTopology::new();
        topology.init_default_distances();

        let mut node0 = NumaNode::new(0);
        node0.start_pfn = 0;
        node0.end_pfn = 512;
        node0.present_pages = 512;
        node0.add_cpu(0);
        node0.add_cpu(1);

        let mut node1 = NumaNode::new(1);
        node1.start_pfn = 512;
        node1.end_pfn = 1024;
        node1.present_pages = 512;
        node1.add_cpu(2);
        node1.add_cpu(3);

        topology.add_node(node0);
        topology.add_node(node1);
        topology.set_initialized();

        assert_eq!(topology.nr_nodes, 2);
        assert!(topology.node_online(0));
        assert!(topology.node_online(1));
        assert_eq!(topology.cpu_to_node(0), 0);
        assert_eq!(topology.cpu_to_node(1), 0);
        assert_eq!(topology.cpu_to_node(2), 1);
        assert_eq!(topology.cpu_to_node(3), 1);
        assert_eq!(topology.node_distance(0, 1), REMOTE_DISTANCE);
        assert_eq!(topology.node_distance(1, 0), REMOTE_DISTANCE);
    }
}

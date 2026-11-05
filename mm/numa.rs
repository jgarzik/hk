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
use crate::util::cpumask::{CpuSet, NR_CPUS};

/// Maximum number of NUMA nodes supported
pub const MAX_NUMA_NODES: usize = 64;

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
    /// CPUs belonging to this node
    pub cpus: CpuSet,
}

impl NumaNode {
    /// Create a new NUMA node
    pub const fn new(node_id: u32) -> Self {
        Self {
            node_id,
            start_pfn: 0,
            end_pfn: 0,
            present_pages: 0,
            cpus: CpuSet::new(),
        }
    }

    /// Check if a CPU belongs to this node
    pub fn has_cpu(&self, cpu_id: u32) -> bool {
        (cpu_id as usize) < NR_CPUS && self.cpus.test(cpu_id)
    }

    /// Add a CPU to this node
    pub fn add_cpu(&mut self, cpu_id: u32) {
        if (cpu_id as usize) < NR_CPUS {
            self.cpus.set(cpu_id);
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
    /// CPU to node mapping, by logical CPU number (set at bring-up)
    pub cpu_to_node: [u8; NR_CPUS],
    /// Firmware CPU id to node, from SRAT / DT (Linux __apicid_to_node)
    hwid_node: [(u64, u8); NR_CPUS],
    /// Entries used in `hwid_node`
    nr_hwid: usize,
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
            cpu_to_node: [0; NR_CPUS],
            hwid_node: [(0, 0); NR_CPUS],
            nr_hwid: 0,
            distance: [[0; MAX_NUMA_NODES]; MAX_NUMA_NODES],
            node_online_mask: 0,
            initialized: false,
        }
    }

    /// Initialize with a single-node fallback topology
    ///
    /// Used when no NUMA information is available (single-socket systems
    /// or systems without SRAT/device-tree NUMA properties). Each CPU
    /// joins node 0 as it comes up (`cpu_up`).
    pub fn init_single_node(&mut self, total_pages: u64) {
        let mut node = NumaNode::new(0);
        node.start_pfn = 0;
        node.end_pfn = total_pages;
        node.present_pages = total_pages;

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

        // Update CPU-to-node mapping from the node's CPUs
        for cpu in node.cpus.iter() {
            self.cpu_to_node[cpu as usize] = node_id as u8;
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
        for (from, row) in self.distance.iter_mut().enumerate() {
            for (to, dist) in row.iter_mut().enumerate() {
                *dist = if from == to {
                    LOCAL_DISTANCE
                } else {
                    REMOTE_DISTANCE
                };
            }
        }
    }

    /// Get the NUMA node for a given CPU
    pub fn cpu_to_node(&self, cpu: u32) -> u32 {
        if (cpu as usize) < NR_CPUS {
            u32::from(self.cpu_to_node[cpu as usize])
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
        if (cpu as usize) < NR_CPUS && (node as usize) < MAX_NUMA_NODES {
            self.cpu_to_node[cpu as usize] = node as u8;

            // Also add it to the node's CPUs if the node exists
            if let Some(ref mut numa_node) = self.nodes[node as usize] {
                numa_node.add_cpu(cpu);
            }
        }
    }

    /// Record the node of the CPU firmware calls `hwid` (x86 APIC id,
    /// arm64 MPIDR affinity); its logical number is not known yet
    pub fn set_hwid_node(&mut self, hwid: u64, node: u32) {
        if node as usize >= MAX_NUMA_NODES {
            return;
        }
        let n = self.nr_hwid;
        if let Some(e) = self.hwid_node[..n].iter_mut().find(|e| e.0 == hwid) {
            e.1 = node as u8;
        } else if n < NR_CPUS {
            self.hwid_node[n] = (hwid, node as u8);
            self.nr_hwid = n + 1;
        }
    }

    /// The node of firmware CPU `hwid`: the first online node if it is
    /// unlisted or its node is offline (Linux puts such CPUs on a node
    /// with memory)
    fn hwid_to_node(&self, hwid: u64) -> u32 {
        self.hwid_node[..self.nr_hwid]
            .iter()
            .find(|e| e.0 == hwid)
            .map(|e| u32::from(e.1))
            .filter(|&n| self.node_online(n))
            .unwrap_or(self.node_online_mask.trailing_zeros() % 64)
    }

    /// Logical CPU `cpu`, firmware id `hwid`, is coming up: map it to its
    /// node (Linux numa_set_node at bring-up)
    pub fn cpu_up(&mut self, cpu: u32, hwid: u64) {
        let node = self.hwid_to_node(hwid);
        self.assign_cpu_to_node(cpu, node);
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
pub fn init_single_node_fallback(total_pages: u64) {
    let mut topology = NUMA_TOPOLOGY.lock();
    if !topology.is_initialized() {
        topology.init_default_distances();
        topology.init_single_node(total_pages);
        crate::printkln!("NUMA: 1 node (fallback), {} MB", total_pages * 4 / 1024);
    }
}

/// Logical CPU `cpu`, firmware id `hwid`, is coming up (arch per-CPU
/// init, after the topology is parsed): record its node
pub fn cpu_up(cpu: u32, hwid: u64) {
    NUMA_TOPOLOGY.lock().cpu_up(cpu, hwid);
}

/// Print NUMA topology summary to console
pub fn print_topology() {
    let topology = NUMA_TOPOLOGY.lock();
    if !topology.is_initialized() {
        crate::printkln!("NUMA: not initialized");
        return;
    }

    crate::printkln!("NUMA: {} node(s) online", topology.nr_nodes);
    for (node_id, node) in topology.nodes.iter().enumerate() {
        if let Some(node) = node {
            let mb = node.memory_size() / (1024 * 1024);
            crate::printkln!(
                "  node {}: {} MB, {} CPUs ({})",
                node_id,
                mb,
                node.cpus.count(),
                node.cpus.fmt_list()
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
        topology.init_single_node(1024); // 4MB
        topology.cpu_up(0, 0);
        topology.cpu_up(3, 7);

        assert_eq!(topology.nr_nodes, 1);
        assert!(topology.node_online(0));
        assert!(!topology.node_online(1));
        assert_eq!(topology.cpu_to_node(0), 0);
        assert_eq!(topology.cpu_to_node(3), 0);
        assert!(topology.get_node(0).is_some_and(|n| n.has_cpu(3)));
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

    #[test]
    fn test_cpus_past_64() {
        let mut topology = NumaTopology::new();
        let mut node1 = NumaNode::new(1);
        node1.add_cpu(64);
        node1.add_cpu(255);
        node1.add_cpu(256); // past NR_CPUS: ignored
        assert!(node1.has_cpu(64) && node1.has_cpu(255));
        assert!(!node1.has_cpu(256));
        topology.add_node(node1);
        assert_eq!(topology.cpu_to_node(64), 1);
        assert_eq!(topology.cpu_to_node(255), 1);

        topology.assign_cpu_to_node(100, 1);
        assert!(topology.get_node(1).is_some_and(|n| n.has_cpu(100)));

        let mut single = NumaTopology::new();
        single.init_single_node(1024);
        single.cpu_up(127, 127);
        assert!(single.get_node(0).is_some_and(|n| n.has_cpu(127)));
    }

    #[test]
    fn test_sparse_hwids() {
        // Firmware ids 0, 2 on node 0; 0x100, 0x102 on node 1 (one node
        // per cluster, sparse ids): logical CPUs 0..3 in bring-up order
        let mut topology = NumaTopology::new();
        topology.add_node(NumaNode::new(0));
        topology.add_node(NumaNode::new(1));
        for (hwid, node) in [(0, 0), (2, 0), (0x100, 1), (0x102, 1)] {
            topology.set_hwid_node(hwid, node);
        }
        for (cpu, hwid) in [(0, 0), (1, 0x100), (2, 2), (3, 0x102)] {
            topology.cpu_up(cpu, hwid);
        }
        assert_eq!(topology.cpu_to_node(0), 0);
        assert_eq!(topology.cpu_to_node(1), 1);
        assert_eq!(topology.cpu_to_node(2), 0);
        assert_eq!(topology.cpu_to_node(3), 1);
        assert!(
            topology
                .get_node(1)
                .is_some_and(|n| n.has_cpu(3) && !n.has_cpu(2))
        );

        // Unlisted id, and a listed one whose node is offline: first
        // online node
        topology.set_hwid_node(9, 5);
        topology.cpu_up(4, 9);
        topology.cpu_up(5, 0x999);
        assert_eq!(topology.cpu_to_node(4), 0);
        assert_eq!(topology.cpu_to_node(5), 0);
    }
}

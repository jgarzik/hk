# NUMA Support Implementation

## Current Status: Phases 1-3 Complete

NUMA (Non-Uniform Memory Access) support for modern x86-64 and aarch64 hardware.

## Completed Work

### Phase 1: NUMA Topology Discovery

**Files:**
- `kernel/numa.rs` - Core NUMA data structures
- `kernel/arch/x86_64/acpi.rs` - SRAT/SLIT parsing
- `kernel/arch/aarch64/dtb.rs` - Device tree numa-node-id extraction
- `kernel/main.rs` - NUMA initialization during boot

**Structures:**
```rust
// kernel/numa.rs
pub struct NumaNode {
    pub node_id: u32,
    pub start_pfn: u64,
    pub end_pfn: u64,
    pub present_pages: u64,
    pub cpu_mask: u64,
}

pub struct NumaTopology {
    pub nr_nodes: usize,
    pub nodes: [Option<NumaNode>; MAX_NUMA_NODES],
    pub cpu_to_node: [u8; MAX_CPUS],
    pub distance: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    pub node_online_mask: u64,
    pub initialized: bool,
}

pub static NUMA_TOPOLOGY: IrqSpinlock<NumaTopology>;
```

**x86-64 Discovery:**
- Parses ACPI SRAT (System Resource Affinity Table) for CPU and memory affinity
- Parses ACPI SLIT (System Locality Information Table) for inter-node distances
- Falls back to single-node if no SRAT found

**aarch64 Discovery:**
- Extracts `numa-node-id` properties from `/memory` and `/cpus/cpu@N` nodes
- Supports optional `numa-distance-map-v1` for distance matrix
- Falls back to single-node if no numa-node-id properties found

### Phase 2: Syscalls Use Real Topology

**Files:**
- `kernel/task/schedsys.rs` - sys_getcpu
- `kernel/mm/mempolicy.rs` - All mempolicy syscalls

**Changes:**
- `sys_getcpu` returns real NUMA node from `NUMA_TOPOLOGY.lock().cpu_to_node(cpu)`
- `sys_get_mempolicy` returns real online node mask
- `sys_set_mempolicy` validates nodemask against online nodes (rejects non-existent nodes)
- `sys_mbind` validates nodemask against online nodes
- `sys_migrate_pages` validates node masks against online nodes
- `sys_move_pages` validates nodes against online nodes, returns -ENODEV for offline nodes

### Phase 3: Per-Task and Per-VMA Policy Structures

**Files:**
- `kernel/mm/mempolicy.rs` - TaskMempolicy struct
- `kernel/task/mod.rs` - mempolicy field in Task
- `kernel/task/percpu.rs` - mempolicy inheritance on fork
- `kernel/mm/vma.rs` - mempolicy field in Vma

**Structures:**
```rust
// kernel/mm/mempolicy.rs
pub struct TaskMempolicy {
    pub mode: i32,           // MPOL_DEFAULT, MPOL_BIND, etc.
    pub nodemask: u64,       // Allowed nodes bitmask
    pub flags: u32,          // MPOL_F_STATIC_NODES, etc.
    pub preferred_node: i32, // For MPOL_PREFERRED (-1 = none)
}

// Added to Task struct:
pub mempolicy: TaskMempolicy,  // Inherited on fork

// Added to Vma struct:
pub mempolicy: Option<TaskMempolicy>,  // Per-VMA policy from mbind
```

---

## Remaining Work

### Phase 4: NUMA-Aware Frame Allocator

**Goal:** Allocate physical pages from specific NUMA nodes based on policy.

**Required Changes:**

1. **`kernel/frame_alloc.rs`** - Per-node allocation regions
   ```rust
   pub struct BitmapFrameAllocator {
       nodes: [NodeAllocator; MAX_NUMA_NODES],
       nr_nodes: usize,
   }

   struct NodeAllocator {
       bitmap: Box<[u64]>,
       base_pfn: u64,
       nr_frames: usize,
       next_free: usize,
   }

   impl BitmapFrameAllocator {
       // Allocate from specific node
       pub fn alloc_node(&mut self, node: u32) -> Option<u64>;

       // Allocate with fallback (try preferred, then others by distance)
       pub fn alloc_prefer(&mut self, preferred: u32) -> Option<u64>;

       // Allocate respecting policy
       pub fn alloc_policy(&mut self, policy: &TaskMempolicy) -> Option<u64>;
   }
   ```

2. **Policy-Aware Allocation Logic:**
   - `MPOL_DEFAULT` / `MPOL_LOCAL`: Allocate from current CPU's node
   - `MPOL_PREFERRED`: Try preferred node, fallback to others by distance
   - `MPOL_BIND`: Only allocate from specified nodes (fail if exhausted)
   - `MPOL_INTERLEAVE`: Round-robin across specified nodes

3. **`kernel/mm/fault.rs`** - Page fault handler integration
   - Get current task's mempolicy or VMA policy
   - Pass policy to frame allocator
   - Use `NUMA_TOPOLOGY.lock().cpu_to_node(current_cpu)` for local allocation

4. **`kernel/mm/syscall.rs`** - Policy-aware mmap/brk
   - Consider mempolicy when pre-allocating pages

5. **Initialization:**
   - `kernel/arch/*/mod.rs` - Initialize per-node regions from topology
   - Use `NumaNode.start_pfn` / `end_pfn` to partition frame allocator

### Phase 5: Page Migration

**Goal:** Implement actual page migration between NUMA nodes.

**Required Changes:**

1. **`kernel/mm/migrate.rs`** (NEW) - Page migration infrastructure
   ```rust
   pub fn migrate_page(
       mm: &MmStruct,
       old_pfn: u64,
       new_node: u32,
   ) -> Result<u64, KernelError> {
       // 1. Allocate new frame on target node
       // 2. Copy page contents
       // 3. Update page tables to point to new frame
       // 4. Free old frame
       // 5. Update reverse mappings (anon_vma)
   }

   pub fn migrate_vma_pages(
       mm: &MmStruct,
       vma: &Vma,
       nodes: &Nodemask,
   ) -> Result<usize, KernelError>;
   ```

2. **`kernel/mm/mempolicy.rs`** - Real implementation of:
   - `sys_migrate_pages` - Find all pages for process, migrate between node sets
   - `sys_move_pages` - Migrate individual pages to specified nodes
   - Query mode (nodes=NULL) should return actual current node for each page

3. **Page-to-Node Tracking:**
   - Need way to determine which NUMA node a physical page belongs to
   - Could use per-node frame allocator ranges for lookup
   - Or add node_id to page metadata if we have struct page equivalent

4. **Locking Considerations:**
   - Page migration requires holding mm lock
   - May need to handle racing page faults
   - TLB shootdown after migration

---

## Testing

Boot tester tests exist in `user/boot_tester/tests/mempolicy.rs`:
- `test_get_mempolicy_basic`
- `test_set_mempolicy_bind`
- `test_mbind_basic`
- `test_migrate_pages_self`
- `test_migrate_pages_null_masks`
- `test_move_pages_query`
- `test_move_pages_node0`
- `test_move_pages_invalid_node`

For Phase 4-5 testing:
- Multi-node QEMU configurations needed (`-numa node` options)
- Verify allocations go to correct nodes
- Verify migration moves pages between nodes
- Test fallback behavior when preferred node exhausted

---

## Key Constants

```rust
// kernel/numa.rs
pub const MAX_NUMA_NODES: usize = 64;
pub const MAX_CPUS: usize = 256;
pub const LOCAL_DISTANCE: u8 = 10;
pub const REMOTE_DISTANCE: u8 = 20;
pub const MAX_DISTANCE: u8 = 255;

// kernel/mm/mempolicy.rs
pub const MPOL_DEFAULT: i32 = 0;
pub const MPOL_PREFERRED: i32 = 1;
pub const MPOL_BIND: i32 = 2;
pub const MPOL_INTERLEAVE: i32 = 3;
pub const MPOL_LOCAL: i32 = 4;
pub const MPOL_PREFERRED_MANY: i32 = 5;
```

---

## References

- Linux kernel: `mm/mempolicy.c`, `mm/migrate.c`
- ACPI SRAT spec: ACPI 6.4 Section 5.2.16
- Device tree NUMA: `Documentation/devicetree/bindings/numa.txt`

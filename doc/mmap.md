# Memory Mapping (mmap) - Gaps and Future Work

## Unimplemented Flags

### PROT_* Flags

| Flag | Value | Description |
|------|-------|-------------|
| PROT_SEM | 0x8 | Atomic ops support |

### MAP_* Flags

| Flag | Value | Description |
|------|-------|-------------|
| MAP_HUGETLB | 0x40000 | Use huge pages |
| MAP_SYNC | 0x80000 | Synchronous page faults (DAX) |
| MAP_UNINITIALIZED | 0x4000000 | Skip zero-fill (embedded only) |

## Recently Implemented

| Flag | Value | Description |
|------|-------|-------------|
| MAP_NORESERVE | 0x4000 | Don't reserve swap (accepted, no effect since we don't reserve swap) |

## Dependencies

- **MAP_HUGETLB**: Requires architecture-specific huge page TLB support
- **MAP_SYNC**: Requires DAX (Direct Access) filesystem support

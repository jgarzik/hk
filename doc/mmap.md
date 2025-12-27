# Memory Mapping (mmap) - Gaps and Future Work

## Unimplemented Flags

### PROT_* Flags

| Flag | Value | Description |
|------|-------|-------------|
| PROT_SEM | 0x8 | Atomic ops support |

### MAP_* Flags

| Flag | Value | Description |
|------|-------|-------------|
| MAP_NORESERVE | 0x4000 | Don't reserve swap |
| MAP_HUGETLB | 0x40000 | Use huge pages |
| MAP_SYNC | 0x80000 | Synchronous page faults (DAX) |
| MAP_UNINITIALIZED | 0x4000000 | Skip zero-fill (embedded only) |

## Known Limitations

1. **No VMA splitting** - mprotect on a partial VMA region updates the entire VMA's protection; a full implementation would split the VMA.

## Dependencies

- **MAP_HUGETLB**: Requires architecture-specific huge page TLB support
- **MAP_SYNC**: Requires DAX (Direct Access) filesystem support

//! Swap and reclaim: swap devices (Linux mm/swapfile.c), the swap
//! cache (swap_state.c), swap entries (swapops.h), the LRU lists
//! (swap.c) and page reclaim (vmscan.c)

pub mod lru;
pub mod swap_entry;
pub mod swap_state;
pub mod swapfile;
pub mod vmscan;

# Known Bugs

## chroot() does not affect path resolution (security)

**Location**: `kernel/fs/path.rs` ~111-119 (absolute-path lookup)

`sys_chroot` records the new root (`fs.set_root`), but path walking
always starts absolute paths at the mount namespace root
(`mnt_ns.get_root_dentry()`) and never consults the task's fs root, so a
chrooted process can still reach everything. `..` at the chroot root is
not clamped either. Boot test `CHROOT` only verifies confinement on a
Linux host (`user/boot_tester/tests/permissions.rs`).

## PID and TID come from separate counters

**Location**: `kernel/task/percpu.rs` do_clone (`next_pid` / `next_tid`)

Linux allocates one ID per task; a single-threaded process has
pid == tid. hk draws pids and tids from separate counters, so e.g.
`fork()`/`clone()` return the child's PID (2) while the child's
`gettid()`, CLONE_PARENT_SETTID/CLONE_CHILD_SETTID stores and futex
TIDs say 3. Anything comparing those values (pthread joins, tgkill to a
returned pid, `/proc/<pid>/task`) can disagree with Linux.

## Raw user-memory copies outside kernel/uaccess.rs

**Location**: `kernel/fs/iov.rs`, `kernel/task/process_vm.rs`,
`kernel/mm/mempolicy.rs`, `kernel/ipc/mqueue.rs`, `kernel/ns/uts.rs`,
`kernel/fs/perm.rs`, and direct `*(ptr as *mut T)` writes (e.g. wait4
status)

Unpopulated-but-valid user pages are now demand-faulted for any kernel
access, but only `copy_{to,from}_user`/`get_user`/`put_user`/
`strncpy_from_user` and `read`/`write` have an exception fixup. Other
sites still copy with `core::ptr` and panic on a truly invalid user
address instead of returning EFAULT; convert them to the uaccess helpers.

## Heap Corruption in Arc<T> Struct Fields

**Status**: Unresolved (workaround in place)
**Discovered**: During USB Mass Storage driver implementation
**Location**: `kernel/usb/msc.rs`
**Affects**: `UsbMscDevice` struct stored in `Arc<T>` within a static `Mutex<Option<Arc<T>>>`

### Symptoms

When an `Arc<UsbMscDevice>` is stored in a static `Mutex<Option<Arc<UsbMscDevice>>>` and later retrieved, certain struct fields contain corrupted values despite:
- The Arc pointer address being identical
- The Arc strong_count remaining correct (3)
- The memory not being freed

### Reproduction

1. Create `UsbMscDevice` with known values:
   - `slot_id = 1`
   - `bulk_in_ep = 0x81`
   - `bulk_out_ep = 0x02`

2. Wrap in `Arc::new()` and store via `set_msc_device()`

3. Verify values immediately after storing - they are correct

4. USB-serial driver probes another device (allocates memory)

5. Retrieve via `get_msc_device()` - values are now corrupted:
   - `slot_id = 6` (was 1)
   - `bulk_in_ep = 0x20` (was 0x81)
   - `bulk_out_ep = 0x00` (was 0x02)

### Debug Output

```
USB-MSC: set_msc_device slot=1 in=0x81 out=0x02 ptr=0x200630
USB-MSC: Field offsets: slot=9, in=10, out=11
USB-MSC: verify after store: slot=1 in=0x81 out=0x02 ptr=0x200630 strong=3
USB: Successfully probed 'usb-msc'
... USB-serial probes ...
USB-MSC: get_msc_device: saved slot=1 in=0x81 out=0x02   <-- atomics correct
USB-MSC: get_msc_device: from Arc slot=6 in=0x20 out=0x00 ptr=0x200630 strong=3  <-- struct corrupted
```

### Struct Layout

```rust
#[repr(C)]
pub struct UsbMscDevice {
    state: Mutex<UsbMscState>,  // offset 0-7 (8 bytes)
    configured: AtomicBool,      // offset 8 (1 byte)
    slot_id: u8,                 // offset 9 (CORRUPTED)
    bulk_in_ep: u8,              // offset 10 (CORRUPTED)
    bulk_out_ep: u8,             // offset 11 (CORRUPTED)
    _pad: u8,                    // offset 12
    max_packet: u16,             // offset 13-14
}
```

The internal `Mutex<UsbMscState>` (at offset 0-7) is also corrupted - attempting to acquire it causes a deadlock, suggesting the lock byte was set to "locked" state.

### Key Observations

1. **Same pointer, different content**: The Arc returns the same address (0x200630) but memory content at offsets 9-11 has changed

2. **Arc metadata preserved**: Strong count remains 3, indicating Arc's internal bookkeeping is intact

3. **Corruption pattern**: Values 0x06, 0x20, 0x00 don't appear random - 0x20 is ASCII space

4. **Timing**: Corruption occurs during USB-serial probe, which allocates its own device structures

5. **Atomics unaffected**: Global static `AtomicU8` values retain correct values, suggesting the issue is specific to heap allocations

### Possible Causes

1. **Heap allocator bug**: May be returning overlapping allocations
2. **Double-free**: Something may be freeing memory still in use
3. **Buffer overflow**: Another allocation may be writing past its bounds
4. **Alignment issue**: Struct may not be properly aligned in heap

### Current Workaround

Store device parameters in global static atomics instead of struct fields:

```rust
static DEBUG_SLOT_ID: AtomicU8 = AtomicU8::new(0);
static DEBUG_BULK_IN: AtomicU8 = AtomicU8::new(0);
static DEBUG_BULK_OUT: AtomicU8 = AtomicU8::new(0);
static DEBUG_TAG: AtomicU32 = AtomicU32::new(1);
static DEBUG_CONFIGURED: AtomicBool = AtomicBool::new(false);
```

These are set during probe and used in `execute()` and `bot_transfer()` instead of reading from `self`.

### Investigation Steps Needed

1. Add heap allocator debug tracing to log all alloc/dealloc with addresses and sizes
2. Check if USB-serial allocation overlaps with UsbMscDevice address
3. Verify frame allocator isn't returning same physical frames to different allocations
4. Test with different struct sizes to see if corruption location changes
5. Check if issue occurs without USB-serial driver present

### Files Involved

- `kernel/usb/msc.rs` - Contains workaround
- `kernel/core/heap.rs` - Heap allocator (prime suspect)
- `kernel/core/frame.rs` - Frame allocator
- `kernel/usb/serial.rs` - USB-serial driver (runs between set/get)

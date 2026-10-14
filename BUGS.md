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

## Raw user-memory access in the pre-VFS minimal write

**Location**: `kernel/arch/x86_64/syscall.rs`

All syscall paths copy user memory through the uaccess helpers (the boot
tests run with SMAP on x86 TCG `-cpu max` and PAN on arm `neoverse-n1`).
The only raw access left is the early minimal `write`, unused once the
VFS handler is registered.

## Network stack gaps (later phases of the network chunk)

**Location**: `kernel/net/`

Listed because real traffic reaches them: TCP has no retransmission or
timers, so a dropped segment (TX ring full, backlog overflow) stalls a
connection, TIME_WAIT ends immediately (no 2MSL), close does not RST
unread data and SO_LINGER is stored only (P6); ARP has no state
machine, every unresolved packet sends a request and entries never
expire (P5); no IP fragmentation/reassembly, so datagrams larger than
the device MTU fail with EMSGSIZE where Linux fragments (P5); no ICMP
errors are generated or delivered (port unreachable, connected-UDP
ECONNREFUSED, IP_RECVERR queue: MSG_ERRQUEUE is always EAGAIN) (P5).
UDP_CORK/MSG_MORE are not implemented (each send is one datagram) and
SO_PEEK_OFF is EOPNOTSUPP. TCP binds share a port only per the
SO_REUSEADDR/SO_REUSEPORT rules; connect() picks an entirely unused
ephemeral port instead of Linux's per-4-tuple reuse.

## Global init is not protected from default-action signals

**Location**: `kernel/signal/mod.rs` send_signal

Linux drops signals with a default action of terminate/stop sent to
global init (SIGNAL_UNKILLABLE), e.g. SIGPIPE from a write to a broken
socket. hk delivers them, so pid 1 (the boot tester) dies. Socket tests
use MSG_NOSIGNAL / SIG_IGN and check SIGPIPE in forked children.

## The initial user stack does not grow

**Location**: `kernel/task/exec.rs` setup_user_stack, `kernel/main.rs`
(init)

The main thread's stack is mapped eagerly at exec (RLIMIT_STACK, or
1 MB when unlimited; init's is 1 MB: it was 16 KB, which made deep
frames fault or hang the boot tester)
and is not a growable VMA: Linux maps it lazily and expands it on demand
up to RLIMIT_STACK.

## NETLINK_ROUTE / SIOC* subset gaps (P3)

**Location**: `kernel/net/netlink/rtnetlink.rs`, `kernel/net/devioctl.rs`

Implemented: link get/dump/change (IFF_UP, MTU), IPv4 address and route
add/delete/dump, route get (output routes), ARP dump, notifications.
Missing, each answered with a Linux errno rather than silently: link
creation and rename (EOPNOTSUPP), multipath routes and nexthop objects
(EOPNOTSUPP), input-route simulation `ip route get ... iif` (EOPNOTSUPP),
NLM_F_ECHO (not echoed), extended-ACK message/offset TLVs (plain errors),
RTM_GETRULE dumps nothing (Linux lists its three default IPv4 rules; there
is no rule engine: lookups are local then main), address lifetimes are
always infinite, promote_secondaries is off.

## Rare arm64 kernel instruction abort in the fault-signal tests

**Location**: unknown (CPU 0, right after `FAULT_SEGV_ACCERR`, i.e. while
`FAULT_SIGILL` runs `udf` in user mode)

Seen once in ~100 `make check-arm` runs (QEMU neoverse-n1 with PAN, -smp
4): "KERNEL PANIC ... exceptions.rs:95" (kernel instruction abort). The
panic handler then dropped formatted messages, so ELR/FAR were lost; it
prints them now. Not reproduced in 90 further runs (sequential and 8 in
parallel). Next occurrence: capture the Message line.

## Partial munmap of an anonymous mapping drops the rest of it

mmap(2 pages) then munmap(second page): mincore on the still-mapped
first page returns ENOMEM (no VMA), where Linux returns 0. Seen while
writing the uaccess boot tests; not investigated.

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

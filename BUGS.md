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

Listed because real traffic reaches them: TCP has no SACK (never
advertised), no CUBIC (only "reno"; Linux defaults to cubic), no
receive buffer autotuning (the window is SO_RCVBUF / 2), no per-netns
RFC 5961 challenge-ACK budget (only Linux's per-connection 500 ms
limit), and TCP_DEFER_ACCEPT / TCP_FASTOPEN are stored only.
tcp_timestamps accepts 0..255 like Linux; any value but 1 sends the raw
ms clock (no offset), as in Linux. No SYN cookies (a full listener drops SYNs). ICMP
timestamp requests are not answered.
Neighbour entries are not confirmed by TCP progress (only ARP), there is
no proxy ARP and no per-device neighbour sysctls (net/ipv4/neigh/*).
IP: no ipfrag_max_dist, no IP options on output (received options are
validated and skipped; source-routed packets are dropped), no
IP_TRANSPARENT. Ping sockets check only the effective gid against
ping_group_range (hk has no supplementary groups). /proc/net/raw and
/proc/net/icmp do not exist.
UDP_CORK/MSG_MORE are not implemented (each send is one datagram) and
SO_PEEK_OFF is EOPNOTSUPP.

## Non-PIE executables cannot be loaded (user space starts at 2GB)

**Location**: `kernel/task/exec.rs` (`load_elf_segments`),
`kernel/arch/x86_64/paging.rs` (`copy_kernel_mappings`, `PAGE_OFFSET`),
`kernel/arch/aarch64/paging.rs` (`copy_kernel_mappings_with_alloc`)

The kernel runs from identity mappings in the low 2GB of every address
space: on x86 the shared PML4[0] maps the first 512MB with 2MB pages
(kernel image at 1MB, heap from ~4MB to 18MB, then the frame
allocator), on aarch64 L1[0]/L1[1] map devices and RAM. User space
therefore starts at 2GB (static-pie binaries load at 0x8000_0000). A
classic ET_EXEC binary linked at 0x400000 collides with those mappings
and execve fails with ENOMEM. Ubuntu's busybox-static is such a binary,
so the busybox end-to-end tests (`tests/busybox.rs`) are skipped on hk
(they pass on Linux). Fix: move the kernel's direct map and image out
of the low half (the planned `PAGE_OFFSET = 0xffff_8880_0000_0000` on
x86, TTBR1 on aarch64) so all of the lower half belongs to user space.

## AF_PACKET gaps

**Location**: `kernel/net/packet/`

Not implemented: SOCK_PACKET (ESOCKTNOSUPPORT), the mmap rings
(PACKET_RX_RING/TX_RING, PACKET_VERSION), PACKET_FANOUT,
PACKET_VNET_HDR, PACKET_QDISC_BYPASS and the other SOL_PACKET options
(ENOPROTOOPT; Linux accepts them), SO_ATTACH_BPF, SO_GET_FILTER, and
socket filters on non-packet sockets (ENOPROTOOPT; Linux runs them on
every socket). A bound socket is not told (ENETDOWN) when its device
goes down later, only when it binds to a down device. Memberships only
count promiscuity/allmulti users (the drivers have no promiscuous or
multicast filtering; set_promisc is a no-op on e1000).
PACKET_AUXDATA reports TP_STATUS_CSUM_VALID only for frames received on
lo (hk has no checksum offload states).

## AF_UNIX gaps

**Location**: `kernel/net/unix/`

No garbage collector for in-flight sockets: a socket whose only
references are messages queued on sockets that are themselves only
reachable that way (e.g. a socket's own descriptor sent to itself, then
closed) stays allocated with its queue. Linux collects such cycles
(net/unix/garbage.c). hk bounds them instead: files in flight are
charged to the sending user and further SCM_RIGHTS sends fail with
ETOOMANYREFS once the count exceeds RLIMIT_NOFILE (Linux's
too_many_unix_fds rule), so a user can pin at most about RLIMIT_NOFILE
files (plus the queues of those sockets, each bounded by SO_SNDBUF and
max_dgram_qlen). Unlike Linux the count is also capped at 2024 (Linux's
UNIX_INFLIGHT_SANE_USER), so raising RLIMIT_NOFILE does not raise what
can be pinned. Socket paths must be UTF-8 (other bytes are EINVAL).

Not implemented: MSG_OOB on streams (EOPNOTSUPP; Linux supports one
out-of-band byte), SO_PEEK_OFF, SO_PASSPIDFD / SCM_PIDFD /
SO_PEERPIDFD, SO_PEERGROUPS, SO_INQ / SCM_INQ, SO_RIGHTS_NOTRUNC,
SIOCUNIXFILE, SO_PEERSEC (ENOPROTOOPT, as on Linux without an LSM).
mknod(S_IFIFO) still creates a regular file.

## File permission (DAC) gaps

**Location**: `kernel/fs/dac.rs`, `kernel/task/exec.rs`

Linux DAC is enforced on the VFS paths (search on every walked directory,
may_open, may_create/may_delete with the sticky rule, owner-only attribute
changes, set-id clearing, capability overrides by fsuid/fsgid). Missing:
no supplementary groups (no setgroups/getgroups; group class checks use the
fsgid only); fs.protected_hardlinks/symlinks/fifos/regular do not exist
(behave as their kernel default 0); execve ignores S_ISUID/S_ISGID and file
capabilities (so MS_NOSUID has nothing to suppress); no
immutable/append-only inodes (no IS_APPEND/IS_IMMUTABLE EPERM);
chmod/chown do not update ctime; ETXTBSY is not enforced.

## Spinlocks where Linux uses sleeping locks

**Location**: `kernel/sync` (Mutex, RwSem), various

Only `i_rwsem`, `s_vfs_rename_mutex` and `f_pos_lock` are sleeping locks
so far. Linux rw_semaphores/mutexes still modeled as `spin` locks include
the mmap lock (`MmStruct`), the mount namespace/topology locks
(namespace_sem, `Mount` RwLocks), `s_umount` (absent), the fd table lock,
pipe locks and RTNL: their holders must not sleep. There are no
`_killable`/`_interruptible`/`try` variants of the sleeping locks yet
(no callers need them).

## Mount flag gaps

**Location**: `kernel/fs/misc.rs` sys_mount/sys_umount2, `kernel/fs/mount.rs`

Honored: CAP_SYS_ADMIN (EPERM), MS_RDONLY (EROFS on every change, on the
superblock), MS_NOSUID/MS_NODEV/MS_NOEXEC (per mount), MS_REMOUNT of those
flags, statfs f_flags and /proc/mounts options. Accepted without effect
because hk already behaves that way: atime flags (no atime updates),
MS_SILENT, MS_MANDLOCK, MS_POSIXACL, MS_I_VERSION, MS_LAZYTIME, and
MS_PRIVATE/MS_UNBINDABLE (mounts never propagate, no bind mounts).
EINVAL instead of Linux behavior: MS_BIND (also MS_REMOUNT|MS_BIND),
MS_MOVE, MS_SHARED, MS_SLAVE, MS_SYNCHRONOUS, MS_DIRSYNC, MS_NOSYMFOLLOW
and umount2 MNT_EXPIRE. Read-only state is one flag, SB_RDONLY on the
superblock (no separate MNT_READONLY: without bind mounts a superblock
has one mount per namespace). Write access (`SuperBlock::want_write`,
Linux mnt_want_write) is held by open-for-write files and across each
modifying syscall; a rw->ro remount is EBUSY while any is held. Unlike
Linux (MNT_WRITE_HOLD), a want_write racing a remount that then fails
with EBUSY can see a spurious EROFS. Not done: mount data/options
strings are ignored; mounts are not user-namespace aware (plain
capable()).

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
add/delete/dump, route get (output routes), neighbour get/dump/add/delete,
notifications (none yet for neighbour state changes: no RTNLGRP_NEIGH;
no proxy ARP entries, NTF_USE or NDA_PROTOCOL).
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

## ramfs has no size limit

**Location**: `kernel/fs/ramfs.rs`, `kernel/mm/page_cache.rs`,
`kernel/frame_alloc.rs`

ramfs (the root filesystem and every ramfs mount) is bounded only by
memory, for every user: writes fail with ENOSPC once free frames reach
the kernel's reserve (1/32 of RAM, at least 4MB) or the kernel heap is
down to 2MB, and the memory comes back when the last link and the last
open reference of a file are gone (or on truncate). Linux's rootfs is a
tmpfs limited to half of RAM by default; tmpfs with `size=`/`nr_inodes=`
limits (and per-user accounting) comes with the filesystem chunk.
Reads of holes need a zeroed page each and can fail with ENOMEM when
memory is at the reserve (Linux maps the shared zero page).

## Partial munmap of an anonymous mapping drops the rest of it

mmap(2 pages) then munmap(second page): mincore on the still-mapped
first page returns ENOMEM (no VMA), where Linux returns 0. Seen while
writing the uaccess boot tests; not investigated.

## The kernel heap is a fixed 16MB region

**Location**: `kernel/main.rs` (`x86_64_heap`, `aarch64_heap`), `kernel/heap.rs`

The heap is one fixed range placed at boot: on x86 from above the
kernel image and multiboot modules/info up to 18MB (where the frame
allocator starts, so ~14MB minus the boot data); on aarch64 16MB at the
first 2MB boundary past the kernel image, DTB and DTB initrd, with the
frame allocator starting at its end. Both arches panic at boot if the
heap would overlap the kernel image or boot data. The heap never grows
and does not draw on the frame allocator, so heap-heavy workloads hit
allocation failure long before RAM runs out; to be fixed with the
allocator redesign (heap backed by frames, slab caches).

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

# hk roadmap

One sequence of phases, in order. Order rule: bugs first, then the
largest blast radius (refactors before more code lands on them), then
dependencies, then the Debian goal (boot Debian trixie from a tmpfs
initramfs: sysvinit now, systemd next). Every phase follows CLAUDE.md:
Linux semantics binding, each commit gated alone, LOCKING.md with each
lock change, a boot test on hk and Linux for new behavior, /code-review
and the heavy gate (uncached gate, LOCKDEP x86+arm, TCG, stress) at
phase end. Gaps a phase leaves go to BUGS.md.

| # | Phase | Why here |
|---|-------|----------|
| 1 | L — locking and atomics bugs | real races, one security-relevant |
| 2 | R2 — pass `&Task`, not tid | largest refactor; before new code |
| 3 | R4 — private TaskInner fields, `Signal` | same object, mechanical |
| 4 | M1 — uaccess and errors | ~400 call sites, mechanical |
| 5 | M2 — arch dedup, IRQ table | IRQ-safe paths needed by 8 and 15 |
| 6 | F — tmpfs/shmem, rootfs on tmpfs | Debian root filesystem |
| 7 | C — group stop, job control, ptrace stops | Debian JOBCTL; VT needs stops |
| 8 | Y — tty and console core | prerequisite of devpts (9) and VT (12) |
| 9 | H — Debian kernel interfaces | DEB_SH, DEB_RCS |
| 10 | I — Debian networking | DEB_NET |
| 11 | T — device topology | SCSI midlayer for AHCI, USB hubs |
| 12 | V — virtual terminals | console, keyboard, logind/Xorg ABI |
| 13 | J — reclaim and OOM | long Debian runs |
| 14 | N — credentials and login | DEB_LOGIN, DEB_SU; check-debian joins the gate |
| 15 | M4 — DMA and MMIO | typed DMA for the real-hardware drivers |
| 16 | D — Dell OptiPlex 3020 bring-up | interrupt routing, xHCI, AHCI, UEFI, NIC |
| 17 | M3 — rest of the bus/DT cleanup | after the drivers settle |
| 18 | M5 — split functions over 150 lines | pure moves |
| 19 | S1 — idioms | small, wide |
| 20 | S2 — docs | last: describes the final code |

Not scheduled: HADL proper (`doc/ideas/HADL-driver-architecture-research.md`:
typed register vocabulary, Ethernet engine, chip descriptions, signed
driver packages and loader, native escape modules). Only its
preparatory items are in the phases above (M1, M2, M4, D's firmware
loading); HADL itself waits for the owner's go-ahead.

## 1. L — locking and atomics bugs

Shared state kept in atomics instead of under its object's lock
(BUGS.md "Atomics audit findings"). Each fix: a repro boot test where
reachable, the LOCKING.md row fixed, the BUGS line deleted.
- L0 LOCKING.md 5.4 rules: lock first, an atomic only for a named
  lockless reader; no check-then-act (one RMW, or Linux's
  add-then-rollback); no `Mutex<()>` beside sibling atomics;
  Release/Acquire for a value that publishes data; `Once` for set-once
  values; per-holder recursion guards; every shared atomic documented;
  an IDA for user-visible ids; per-CPU counters on hot paths. Drop the
  wrong "correct" examples (Inode mode/uid/gid, MsgQueue,
  SemArray.pending).
- L1 ipc/sem semop: semval/sempid under the array lock; check, apply,
  removed-check and enqueue under it, wake after unlock (Linux
  sem_lock); SETVAL/SETALL/exit_sem under it.
- L2 chmod/chown under i_rwsem across the permission check, privilege
  drop and id/mode/ctime update (Linux notify_change).
- L3 cgroup pids: charge in can_fork on the target set, cancel on
  failure (Linux pids_can_fork).
- L4 i_size with Release/Acquire (i_size_write/read); fallocate under
  i_rwsem.
- L5 ipcget under the ids lock; shm_tot/used_sems updated after insert,
  under it.
- L6 mount flags under mount_lock; MNT_WRITE_HOLD, RDONLY set only on
  success.
- L7 kcmp cookies set once at boot; Key.state CAS on instantiate,
  revoke/update under the payload lock; MsgQueue state under
  `messages` plus the IPC_SET qbytes EPERM ABI; NTP state in the
  TimeKeeper seqlock, ADJ_SETOFFSET through inject_offset.
- L8 cgroup_mutex and cgroup_threadgroup_rwsem (rmdir vs attach).
- L9 TCP shutdown/disconnect bits and `connecting` under `cb`.
- L10 TCP memory: per-CPU forward allocation, tcp_mem scaled to RAM.
- L11 low batch: GroupCputimer started only by arming; timer wheel
  `not_before` under the wheel lock; workqueue fields under their lock;
  PacketSock bind as one update; zone watermarks under zone.lock; heap
  init `Once`; filemap mkclean by swap/CAS; blkdev open counters under
  open_mutex, capacity/ro plain; NR_CPU_IDS set once before any user.
- L12 delete dead atomics; cgroup io/cpu/memory/freezer counters in
  Linux's shape (page_counter, token bucket under its lock).
- L13 `get_user`/`put_user` accept unaligned user pointers (Linux
  does); boot test on both kernels first.

## 2–4. R2, R4, M1 — the large mechanical refactors

- R2 `get_task_*(tid)` helpers take `&Task` or use `current()`;
  tid-to-task lookup only at the syscall boundary (kill, ptrace,
  waitid, pidfd, /proc), holding `Arc<Task>`; TASKLIST row updated.
- R4 TaskInner's public fields become private with accessors;
  `exit_signal`/`pdeath_signal` become `Option<Signal>`; FutexKey
  fields private.
- M1 non-generic `get_user`/`put_user`/`copy_*` (no `::<Uaccess,`
  turbofish); `From<UaccessError> for KernelError`; IoremapError and
  IRQ string errors become KernelError; a `SysRet` trait so `sys_*`
  return `KernelResult` with `?`; one public `fget` for the open-coded
  fd lookups; redundant `access_ok` checks dropped; raw errno literals
  replaced.

## 5. M2 — arch dedup and the IRQ table

`IrqSpinlock` in `sync/irqspin.rs` over arch `local_irq_save/restore`;
generic ioremap allocator (one IOREMAP_END); kmap skeleton generic;
generic IRQ table with typed RAII `request_irq<T: IrqHandler>`.

## 6. F — tmpfs/shmem and rootfs on tmpfs

shmem on the page cache (swap-backed; size=, nr_inodes=, mode, uid,
gid; statfs); rootfs is tmpfs (50% of RAM), the cpio unpacked into it,
initrd pages freed; devtmpfs, SysV shm and MAP_SHARED|MAP_ANONYMOUS
on shmem; memfd_create with seals; O_TMPFILE; fallocate punch/zero.
Tests TMPFS_LIMITS, MEMFD_SEALS, ROOTFS_TMPFS.

## 7. C — group stop, job control, ptrace stops

Group stop and continue (SIGSTOP/TSTP/TTIN/TTOU defaults, SIGCONT,
CLD_STOPPED/CLD_CONTINUED, orphaned process groups); wait4/waitid
WUNTRACED/WCONTINUED/WSTOPPED; SIGTTIN/SIGTTOU on background tty I/O
(tty_check_change stops instead of failing); shared pending queue with
Linux's thread choice; ptrace_stop (signal-delivery, syscall, exec
stops), FOLL_FORCE for POKE; reboot CAD_ON/CAD_OFF. Tests JOBCTL,
WAIT_STOPPED, PTRACE_STOP.

## 8. Y — tty and console core

- Tty open counts and release; TtyDriver ops (install, close, ioctl
  fall-through, resize, stop, start, init_termios) on the serial
  drivers.
- Console core: register_console with console= rules, preferred
  console and CON_CONSDEV order, `console_device` for /dev/console,
  arm64 stdout-path, per-console log replay, /proc/consoles,
  earlyprintk/earlycon boot consoles. `console/active` stays in Linux
  order.
- IRQ-safe deferred work (static, intrusive, no allocation); each port's
  flip buffer pushed by its own work item.
- ioremap_wc (x86 PAT WC, arm64 Normal-NC) and bulk IoMem copies.
- Hangup: __tty_hangup for vhangup, TIOCVHANGUP, session-leader exit,
  carrier loss and port removal (hung-up file ops: EIO, POLLHUP),
  SIGHUP/SIGCONT, controlling tty cleared; per-process controlling
  tty.
- `-vga std` pinned in run-qemu.sh and linux-boot-tester.sh.

## 9. H — Debian kernel interfaces

devpts and ptys (ptmx, TIOCGPTN/TIOCSPTLCK/TIOCGPTPEER, newinstance);
/proc: cmdline, stat, uptime, loadavg, filesystems, cpuinfo, swaps,
devices (with the block section), sys/kernel/{hostname, osrelease,
ostype, random/{boot_id,uuid,entropy_avail}, pid_max, cap_last_cap,
printk}, pid/{comm, cwd, root, limits, oom_score_adj}; uname release
in Linux form; harness `tools/debian-root.sh` (apt-get download,
dpkg-deb -x, fakeroot cpio) and `check-debian{,-arm}`, cached by input
hash. Tests PTY_BASIC, PROC_BASICS, DEB_SH, DEB_RCS.

## 10. I — Debian networking

ifupdown with dhclient (AF_PACKET and raw paths);
/proc/sys/net/ipv4/{conf,neigh}/*, /proc/net/{snmp,raw,icmp}; SIOCETHTOOL
where dhclient or ifup need it; Linux errnos where AF_INET6 is tried.
Test DEB_NET (DHCP on QEMU slirp, ip addr, ping, TCP fetch, DNS).

## 11. T — device topology

Missing intermediate subsystems, built in Linux's shape (no faked
paths):
- T1 SCSI midlayer: Scsi_Host and the scsi_host class, the scsi bus
  with targets and devices and their scan, sd as a scsi driver bound to
  disk devices, scsi_device attributes, the scsi_disk class;
  usb-storage registers a host per interface. Prerequisite of AHCI.
- T2 USB: both xHCI root hubs (USB2 and USB3 port ranges), the hub
  driver (port devices, port-status hotplug, route strings, B-P.P
  names), usbfs /dev/bus/usb.
- T3 amba bus: DT primecell devices (periphid, amba:d MODALIAS); PL011
  and PL031 move onto it. ECAM and DT device info from the device tree
  through arch callbacks.
- x86 ttyS0 below the ACPI PNP0501 device waits for ACPI namespace
  enumeration (D).

## 12. V — virtual terminals

Linux drivers/tty/vt equivalence:
- P1 VT core and dummycon: tty1..63 and tty0, con_write C0 controls
  and scrolling, the VT console (console=tty0/ttyN), KDGKBTYPE,
  VT_GETSTATE, VT_OPENQRY.
- P2 escape/CSI parser, SGR and palette, G0/G1 and consolemap, cp437
  and UTF-8, DSR/DA responses; /dev/vcs, vcsa, vcsu.
- P3 renderers: vgacon and fbcon (no scrollback, as Linux); the panic
  path; `make check-gfx` outside the gate.
- P4 switching and modes: VT_ACTIVATE/WAITACTIVE/SETMODE/RELDISP,
  KDSETMODE, VT_DISALLOCATE, VT_RESIZE, VT_LOCKSWITCH, TIOCLINUX
  subset; /sys/class/tty/tty0/active with poll.
- P5 input core, evdev (EVIOC* subset, grab, revoke, mask), uinput;
  /sys/class/input with uevents.
- P6 keyboard handler: keymaps, all key handlers, four modes, unicode,
  diacritics, the KD* keyboard ioctls, LEDs, Alt-Fn,
  Ctrl-Alt-Del.
- P7 keyboard hardware: xHCI interrupt endpoints, USB HID boot
  keyboard, i8042/atkbd, virtio-input.
- P8 fonts and maps: KDFONTOP, unimap and screen-map ioctls, colormap,
  KIOCSOUND/KDMKTONE.
- P9 virtio-gpu 2D (checked in check-gfx).

## 13. J — reclaim and OOM

kswapd, priority reclaim, the slab shrinker API, the OOM killer with
oom_score_adj. Test: 1000 fork+exec of a dynamic binary with slab flat;
OOM kill semantics.

## 14. N — credentials and login

setuid/setgid exec and file capabilities (NOSUID honored),
PR_CAPBSET_*, ambient capabilities, securebits; interactive login on a
pty. Tests DEB_LOGIN (agetty autologin, bash job control), DEB_SU.
`check-debian{,-arm}` joins `make gate`.

## 15. M4 — DMA and MMIO

The streaming DMA API kept and typed (no raw physical addresses, unmap
on completion), `DmaAddr` with a private constructor, `DmaRing<T: Pod>`
with volatile access (e1000, then virtio, xHCI), xHCI rings through
the DMA API, ordered IoMem writes plus `_relaxed` variants, PL011/
PL031/xHCI registers on IoMem, xHCI quirks as bitflags; releases the
matching BUGS.md "unsafe not yet wrapped" items.

## 16. D — Dell OptiPlex 3020 bring-up

In the Dell order: IOAPIC with ACPI _PRT routing, MSI and MSI-X (x86
LAPIC messages; arm64 GICv3 ITS/GICv2m on QEMU virt), ACPI namespace
enumeration enough for PNP devices; request_firmware (Linux
firmware_class paths); xHCI on Lynx Point; AHCI 8c02 through libata
and SAT on the SCSI midlayer; UEFI boot; RTL8168g.

## 17–20. M3, M5, S1, S2

- M3 aarch64 DT information in its own type, not AcpiInfo; remaining
  "(stub for now)" banners.
- M5 the 21 functions over 150 lines (do_clone, bpf_run, sys_prctl,
  kmain, sys_mmap, exec_file, tty_ioctl, sys_fcntl, do_semctl,
  do_select_internal, sys_mremap, procfs_mount, the NUMA/SRAT parsers,
  exit_current, both setup_rt_frame, fanotify_mark, waitid, adjtimex,
  setns) split into per-command or per-step helpers.
- S1 O(n²) VMA loops to iterators; sentinels to Option;
  `from_ne_bytes(..try_into().unwrap())` to `pod!`; `current_mm()`;
  `new_without_default` allowed and the trivial `impl Default` deleted;
  let-else; stale `allow(dead_code)` removed; struct-update syntax;
  `then`/`then_some`; one LE/BE byte reader, no slice `unwrap` on
  device or disk data; `next_multiple_of`; pointer-cast lints.
- S2 `# Arguments`/`# Returns` blocks and `// ====` banners removed;
  history and speculative comments rewritten to the current state;
  `TODO(unsafe)` lines kept.

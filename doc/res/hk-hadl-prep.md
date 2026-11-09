# hk: preparing for HADL (loadable, description-driven drivers)

Design and plan, from doc/ideas/HADL-driver-architecture-research.md. doc/ROADMAP.md schedules only the preparatory items (M2, M4, D; M1 is done); H2–H7 (HADL proper) are not scheduled.

## 0. Constraints

| # | Topic | Rule |
|---|---|---|
| 1 | Runtime driver loading | Required, high priority: hk designs its own module/driver loader and API; Linux .ko compatibility is not a goal. |
| 1a | What a loadable driver contains | Everything the driver needs to operate, per HADL (§3 defines the package). |
| 1b | init_module / finit_module / delete_module | **Front the hk loader**: same syscalls, /proc/modules, CAP_SYS_MODULE, modules_disabled; they take hk driver packages, not ELF .ko. |
| 2 | AHCI path | **libata/SAT**: ATA through the SCSI layer (sdX, SG_IO, ATA passthrough), as Linux. |
| 3 | Dell boot | **UEFI** → IOAPIC + MSI/MSI-X routing is a prerequisite for RTL8168g and AHCI. |
| 4 | Firmware | **request_firmware** (Linux API; /lib/firmware search, initramfs). |
| 5 | Ethernet engine location | **hw/net/eth.rs** (touches DMA/IRQ). |
| 6 | QEMU e1000e (82574) | **Yes**, CI-only second Intel family. |
| 7 | NIC data path | **Zero-copy from the start** (page_pool-style buffer pools in the engine). |
| 8 | mmiotrace | **Yes**, optional cargo feature. |
| 9 | Signing | **Built-in keyring** (Linux .builtin_trusted_keys): public keys compiled into the kernel; packages signed by `tools/hkd`; Ed25519 over the content hash (SHA-256 or BLAKE3, pick one in H5). |
| 10 | Escape hooks after built-in Rust | **Native first** (signed, trusted, hk C-ABI, H7); a small verified IR only if a need appears later. |
| 11 | Package delivery | **Files + init_module**: initramfs and /lib/modules/<release>, loaded by modprobe/insmod through finit_module/init_module; no kernel auto-fetch. |
| 12 | Unsigned packages | **Allowed with a warning and taint** unless signature enforcement is on (cmdline/config), as Linux. |

## 1. Targets in the code

- e1000.rs and virtio_net.rs duplicate one NAPI skeleton (poll: swap causes, link, tx reclaim, rx under lock, deliver after unlock, napi_complete_done + rearm under rx with netif_running and MISSED recheck; open; stop; 2 KiB bounce per descriptor; Ops glue + wrapper). Per-chip: cause ack/mask, ring format and doorbell, link status. That is the engine boundary.
- e1000 descriptors: raw volatile field writes through DmaCoherent::cpu_addr; publish-last coded by hand. Registers are bare consts (nothing says ICR is read-clear, IMC/IMS write-only). reset() spins a fixed iteration count without a time base (`hw/net/e1000.rs`).
- xhci: two `Trb` types (`hw/usb/xhci.rs`, `hw/usb/transfer.rs`), three open-coded cycle-bit rings, u32 quirks + match, global USB_CONTROLLER.
- IRQ: `fn(u32, *mut ()) -> bool` with raw `*mut ()` casts in ISRs (`arch/x86_64/irq.rs`).
- Block: blk-mq `MqOps` (queue_rq/commit/complete in hardirq under hctx IrqSpinlock) is a sound engine boundary; block/scsi.rs `ScsiHost` (USB mass storage) is the base for libata/SAT.
- Net: `SkBuff` (net/skb.rs), `netif_rx`/`netif_receive_skb` (net/core/dev.rs), `NetDeviceOps::xmit(Box<SkBuff>)`.
- Helpers to build on: hw/pci/quirks.rs `PciFixup`, hw/virtio/ring.rs `Vring` + host `Fake` device (test template), arch barriers (dma_wmb/dma_rmb/wmb), util/pod.rs, bitflags, offset_of!.
- Missing for the Dell: IOAPIC/MSI (BUGS.md), request_firmware, libata, RTL8168g driver, module loader.

## 2. Architecture

HADL's axes stay separate (doc §4): authoring (Rust | HADL), artifact (package), loading (data instantiation | native relocation), execution (in-kernel now; compartments later), hardware authority (mediated vs direct).

Layers:
1. **Class cores** (Linux-shaped, generic, outside hw/): net/core NAPI + netdev, block blk-mq, SCSI + libata/SAT, usb core, input (VT plan).
2. **Engines** (hw/, trusted Rust built into the kernel): `EthDev<H>` (hw/net/eth.rs), later `AhciPort` (libata host), `PhaseRing` xhci core, NVMe queues. Engines own locking, DMA lifetime, IRQ/NAPI protocol, buffer pools.
3. **Hardware vocabulary** (hw/): typed registers, descriptor rings with ownership/phase models, wait/handshake, quirk flags, RegIo backend.
4. **Descriptions**: data that configures an engine (`NicFamily` etc.). Built-in as const Rust data first, then the same schema loaded from packages.
5. **Escapes**: named hooks for logic the vocabulary can't express (PHY magic, ME workarounds): built-in Rust first; native code in packages later through the hk driver ABI.
6. **Loader**: hk driver packages via init_module/finit_module.

Trust model (doc §7, Q6 recommendation): data-only packages are validated and bounded (no code); native escape code is a **trusted, signed fallback** until hardware compartments exist. Dangerous authority (PCI config writes beyond the declared set, reset of shared functions, DMA domain changes, firmware flashing) is kernel-mediated, never raw.

## 3. The hk driver package (what a loadable driver contains)

A package is everything a driver needs, self-describing and versioned. Container: a small, fixed binary format of typed sections (not ELF for data packages; native code sections carry their own relocatable image).

| Section | Contents | Notes |
|---|---|---|
| `HEAD` | magic, package format version, package name/version, content hash (BLAKE3/SHA-256 of all sections), flags | rejected if format unknown |
| `SIGN` | Ed25519 signature over the content hash, key id into the built-in keyring | unsigned or unknown-key packages load with a warning + taint unless enforcement is on (cmdline/config, Linux module.sig_enforce); enforced → EKEYREJECTED |
| `MATCH` | device table: PCI vendor/device/subvendor/subdevice/class/mask/revision range; DT compatible strings; ACPI HIDs; priority; MODALIAS strings | drives autoload (modalias) and binding; conflicts resolved by priority, then rejected |
| `ENGINE` | required engine id + semver range (e.g. `ethernet_dma >=1.0,<2`), required optional features (checksum offload, multiqueue, PTP...) | load fails cleanly on mismatch |
| `CAPS` | resource claims: BARs (index, min size, MMIO/IO), DMA mask, DMA memory budget, IRQ vectors (MSI-X count / MSI / INTx), PCI config registers it may touch, power states | the kernel enforces: offsets are validated against claimed BARs, allocations against budget |
| `REGS` | register map: name id, BAR, offset, width, array stride/count, access (RO/WO/RW/RC/W1C), side-effect class (doorbell, reset, irq-ack), readback/flush rule | maps to `Reg<W, A>` |
| `DESC` | descriptor layouts: size, alignment, endianness, fields (offset/width/bit ranges), tagged variants (legacy/extended/context), DMA address fields, owner/DD/EOP/SOP/error decode | maps to `DmaRing<T>` field tables |
| `QUEUE` | queues: pattern (head_tail, owner_bit, phase), size limits, producer/consumer roles, doorbell register + value rule, wrap policy, completion rule, batching, queue→vector map | maps to ring models |
| `IRQ` | pattern (mask_poll_rearm), cause/ack/mask/unmask registers and semantics, link-change cause bits, moderation registers | maps to `EthHw` irq ops |
| `LIFE` | bounded state machines: probe, reset, init, start, stop, suspend, resume, recover: op lists (`W32/Set32/Clr32/Wait32{mask,want,timeout}/Delay/Hook/Fail`), no loops, fixed op count, explicit error transitions | interpreted by the engine's bounded script runner |
| `VAR` | variants/quirks: predicates (revision, subsystem, MAC version register value) → overrides (ops, flags, capability bits), with provenance (source: Linux file/function) | revision selection at probe |
| `FW` | firmware references: name (rtl_nic/rtl8168g-2.fw), required/optional, expected hash, load stage | resolved by request_firmware; blobs never embedded unless license allows |
| `HOOK` | named escape hooks used by LIFE/VAR, bound to built-in hooks (by id) or to native code in `CODE` | unresolved hook → reject |
| `CODE` | optional native escape object for this arch: position-independent code+data, relocation list, imports (hk driver ABI symbols by name+version), exports (hook ids → entry points) | W^X mapping, relocations validated, imports resolved only against the ABI table |
| `SRC` | optional canonical HADL source hash/URL (reviewable source cross-link; doc §5 source identity) | informational |

Lifecycle (doc §5.7, §7): `Loaded → Bound → Running → Quiescing → Revoking → Resetting → (Running | Failed) → Unbound → Unloaded`. Reference counts cover package, device, queues, DMA mappings, IRQ registrations, hook code. delete_module succeeds only after IRQ quiescence, DMA fencing/reset, work drain, and zero references (O_NONBLOCK semantics as Linux: EWOULDBLOCK/EBUSY).

### Syscalls and user interface (front the hk loader)
- init_module(image, len, params) / finit_module(fd, params, flags): parse + validate package, check CAP_SYS_MODULE and modules_disabled, signature policy; register its MATCH table; bind to present unbound devices. Errors per Linux errno meanings (EPERM, ENOEXEC for a malformed package, EEXIST, EKEYREJECTED for a bad signature, ENOENT for a missing engine, ...).
- delete_module(name, flags): Linux semantics on an hk package.
- /proc/modules, /sys/module/<name> (sysfs phase SYS): name, size, refcount, state; /sys/bus/pci/drivers/<drv>/{bind,unbind,new_id}; taint in /proc/sys/kernel/tainted.
- Autoload: device discovery emits MODALIAS; kernel request_module → usermode helper /sbin/modprobe (Linux path) so modprobe/insmod/rmmod work with hk packages (modules.alias generated by an hk tool from MATCH sections). Prerequisite: call_usermodehelper.
- Packages live in initramfs and /lib/modules/<release>/ as `.hkd` files; only user space (modprobe/insmod) hands them to the kernel; the kernel never fetches packages itself.

### Native escape ABI (`CODE`) — later phase
- `#[repr(C)]` versioned API table (`HkDriverApi { version, size, fns... }`) passed to the module's init: register access through engine handles (opaque), DMA via handles (no physical address fabrication), sleep/delay, logging, firmware fetch. No Rust ABI across the boundary; panics abort the hook and fail the device (Failed state), never unwind into the kernel.
- Rust SDK crate (separate workspace under tools/ or a new sdk/) that builds `CODE` sections from safe Rust against the ABI.

## 4. Preparatory phases (largest blast radius first; each commit bisectable, converts its users, LOCKING.md in the same commit)

### H0 — interrupt routing and firmware (prerequisites, Dell UEFI)
- H0.1 IOAPIC (ACPI MADT, _PRT routing via ACPI tables), x86 IRQ domain; PIC only as fallback.
- H0.2 MSI and MSI-X (PCI capability parsing, x86 LAPIC message address/data, arm64 GICv3 ITS / GICv2m on QEMU virt), per-vector registration in the generic IRQ table.
- H0.3 request_firmware / release_firmware (Linux firmware_class semantics: /lib/firmware/updates, /lib/firmware, initramfs; uevent fallback off), firmware hash check when the package declares one.
Size L; risk high (interrupt delivery is everything). Tests: MSI-X on virtio-net/virtio-blk in QEMU (x86 + arm64), firmware load boot test (on Linux and hk: a test firmware in initramfs read through a test hook, or via a driver that needs firmware).

### H1 — planned series items, shaped for HADL (M3/M4)
- PCI ID tables carrying typed family data (`PciDeviceId<D> { ..., data: &'static D }`, `PciDriver<D>`, `PciDriverDyn`; the Linux-shaped untyped `PciDeviceId`/`PciIds` and dynamic ids exist), revision matching; PciFixup on the same matcher. This is the in-kernel form of the package `MATCH` section.
- Typed `request_irq<T: IrqHandler>` RAII (`IrqReturn`, `IrqRegistration`), MSI-X vectors (H0.2) included.
- `DmaRing<T: Pod>` split into memory (volatile element/field access, `publish(i, v, own_field)`) and index/ownership state; `Field<T, F>` + `field!`; Le16/32/64 Pod newtypes.
- IoMem ordered + `_relaxed` + a `RegIo` trait (engines generic over `R: RegIo = IoMem`), `MockRegs` for host tests.
- DmaAddr private constructor (`hw/dma.rs`: `pub struct DmaAddr(pub u64)`), xhci quirks as `PciDeviceId<XhciQuirks>` data.

### H2 — hardware vocabulary
- Typed registers `Reg<W, A>` (Ro, Wo, Rw, Rc, W1c), `RegArray`, `regs!` macro: the in-kernel form of `REGS`. Converts e1000, xhci, virtio common cfg.
- Ring models: `HeadTail`, `PhaseRing` (one Pod `Trb`), `OwnerRing` with RTL8168g: the in-kernel form of `QUEUE`.
- `wait_bits` on poll_timeout; replaces e1000 spin and xhci handshake.
- Bounded op script runner (`Op` enum, `LIFE` form) used first by built-in e1000/e1000e reset/init, so it lands with users.
- `mmiotrace` cargo feature: RegIo backend that logs every access (format compatible with Linux mmiotrace text for diffing).

### H3 — Ethernet engine with zero-copy buffers (hw/net/eth.rs)
- `EthDev<H: EthHw>`: owns rx/tx locks, NAPI poll (budget, deliver after unlock, complete + rearm under rx, MISSED recheck), open/stop, stats, LOCKING rows move to `EthDev.{rx,tx}` (same class/order).
- `EthHw` trait: irq_causes / irq_mask / irq_unmask -> bool / link_up / tx_post(desc set) / tx_clean / rx_post(buffers) / rx_clean(f) / doorbells / start / stop.
- **Zero-copy (Q7):** per-RX-queue `PagePool` (Linux page_pool): pages DMA-mapped once, recycled when the stack frees the SkBuff; RX descriptors point at pool fragments; received frames become `SkBuff`s that reference pool pages (frag ownership + release callback) instead of copied buffers. TX: map `SkBuff` data (linear + frags) directly via the DMA API (streaming map, unmap on completion) with scatter/gather descriptors where the ring supports it; copy only below a small threshold (Linux copybreak). Requires: SkBuff page fragments + destructor (net/skb.rs), streaming DMA map/unmap (the API, kept and typed in M4, reshaped for the engine), cache sync on non-coherent arm64.
- Converts e1000 and virtio-net (two commits, each gated).
- Host tests: fake `EthHw` (budget, rearm race), pool recycle, ring models; QEMU throughput baseline before/after.

### H4 — second families and descriptions
- e1000e (82574) in QEMU CI on `EthDev` (Q6), first as built-in Rust.
- RTL8168g native on `EthDev` (Dell; needs H0 + firmware), adding `OwnerRing`.
- Extract `NicFamily` const descriptions from e1000/e1000e/RTL8168g: `REGS/DESC/QUEUE/IRQ/LIFE/VAR/FW` as Rust data, hooks as built-in fns. Chip files shrink to description + hooks. LOC ledger (doc §8 D): engine + vocabulary + descriptions + hooks.

### H5 — package format and loader (dynamic loading, data-only)
- Package container (`HEAD/SIGN/MATCH/ENGINE/CAPS/REGS/DESC/QUEUE/IRQ/LIFE/VAR/FW/HOOK`), built-in keyring + Ed25519 verification, taint for unsigned, bounded parser and validator in the kernel (every offset against claimed BARs, field layouts against descriptor size, op counts, engine version, hook ids against the built-in hook table), deserializes into the exact `NicFamily` structs from H4.
- `tools/hkd`: host tool that builds packages from the H4 Rust const descriptions (or HADL source later), signs them, and emits modules.alias.
- init_module / finit_module / delete_module fronting the loader; /proc/modules; CAP_SYS_MODULE; modules_disabled; signature enforcement; device rebinding on load; unload state machine (§3).
- request_module + call_usermodehelper + MODALIAS autoload.
- Tests (hk + Linux where the syscall contract is shared: EPERM without CAP_SYS_MODULE, modules_disabled, ENOEXEC for junk; hk-only for package load/unload): load the e1000e package from initramfs after boot with the built-in description removed, traffic, unload, reload; negative tests (malformed offsets, out-of-range fields, conflicting IDs, bad hash/signature, unsupported engine version, invalid DMA width) per doc Phase C.
- Exit (doc Phase C): runtime install/load/unload of a chipset without rebuilding the kernel; other devices unaffected by failures.

### H6 — storage and USB on the same model
- libata core + SAT (Q2) on block/scsi.rs; `AhciPort` engine (command list, FIS, PxCI doorbell, PxIS W1C, NCQ tags); AHCI 8c02 on the Dell, ich9-ahci in QEMU; shared `Tags` slot bitmap with virtio-blk.
- xhci per-controller + `PhaseRing`; quirks as package `VAR` data.

### H7 — native escape modules
- hk driver ABI (`HkDriverApi`), `CODE` section loader (relocation validation, W^X, import resolution against the ABI table only), SDK crate, signing as for data packages (taint when unsigned and not enforced). First user: a hook moved out of a built-in RTL8168g PHY config into a package. A verified IR for hooks stays research until a need appears.

### Later research (kept visible, not scheduled)
Bytecode/IR for complex escapes with a verifier; JIT only if measured; userspace or VMX/EL2 compartments; IOMMU/SMMU domains; vendor-produced descriptions from SystemRDL/SVD.

## 5. First proof (doc Phase A–D mapped to hk)
1. H3 with e1000 + virtio-net (CI devices): engine boundary proven, zero-copy path in place, throughput not regressed.
2. H4 e1000e (CI) + RTL8168g (Dell): cross-vendor (head/tail vs owner-bit rings), revisions, firmware.
3. H5: the e1000e description loaded as a package from initramfs, unloaded, reloaded.
Success: chip files contain no `unsafe`; e1000 ≤ ~300 lines (description + hooks), RTL8168g ≤ ~500 (excl. PHY tables); host tests for engine, rings, pools, package validator; no throughput/latency regression; LOCKING.md engine section; LOC ledger per doc §8 D; every commit gated.

## 6. Risks
- Interrupt routing (H0) gates all real-hardware work; MSI-X on arm64 needs ITS/v2m.
- Zero-copy touches the net stack's buffer ownership (SkBuff frags, destructors, page lifetime vs pool); needs careful LOCKING and lifetime rules; arm64 non-coherent sync if ever targeted.
- RTL8168g PHY magic and firmware variants (Linux rtl8168g_1 hw_phy_config).
- Package validator is new attack surface: fuzz it on the host (cargo test with corpus).
- Unload safety across IRQ/DMA/SMP (doc §7): needs DMA fencing (bus-master disable + reset) before freeing memory.

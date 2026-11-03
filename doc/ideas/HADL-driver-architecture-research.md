# HADL: Declarative, Dynamically Loadable Drivers for the Rust OS Kernel

**Status:** Research and architectural decision record; 2026-11-03.  
**Audience:** AI coding agent maintaining the Rust OS kernel (Tulip/MyKernel), and its human maintainer.  
**Mission:** **Most driver code never has to be written.**

## 0. Executive direction

The accepted priority is **minimum aggregate maintained source lines across all supported hardware**, without unacceptable performance, correctness, or maintainability tradeoffs. A small *device-specific* file is not a success if it requires an enormous, brittle generic engine. Devices **must** be dynamically loadable: building every possible x86-64 driver into the kernel is not feasible. This applies by extension to AArch64.

**Accepted design direction:** Create HADL (provisional name), a domain-specific language for describing chipset families, their registers, DMA layouts, queue protocols, interrupts, lifecycle and quirks; provide reusable Rust engines for device classes such as Ethernet and storage. Preserve an architecture-neutral, typed representation and a future path to verified bytecode/JIT and hardware-isolated execution. Native Rust remains an essential bootstrap and escape hatch.

**Current preferred implementation sequence (a recommendation, not an irrevocable acceptance):**

1. Analyze real independent NIC drivers and catalog recurring patterns.
2. Prototype one optimized Rust Ethernet engine and HADL schema with a **userspace/offline compiler** and generated static Rust for rapid kernel bring-up.
3. Add a **dynamic data-driven driver package loader**, resolving portable descriptions against trusted built-in engine implementations. This meets the dynamic-loading requirement **without** requiring an in-kernel Rust compiler, JIT, or general ELF linker for HADL packages.
4. Define a versioned, typed IR if necessary for complex state-machine/exception logic. Use AOT native compilation where data-driven interpretation is too costly; add JIT only when profiling justifies it.
5. Add a separate native Rust module loader for devices that cannot fit the DSL, using a narrow versioned C-compatible ABI rather than unstable Rust ABI.
6. Explore strong compartments (VMX/EPT, AMD SVM/NPT, AArch64 EL2/Stage-2) and IOMMU/SMMU after the capability architecture and performance baseline exist.

**Decision caveat:** The user explicitly accepts the DSL-first strategy, reduced aggregate LOC, dynamic loading, and keeping bytecode alive. Whether the shipped canonical artifact is source, portable IR, or both; precise runtime/compiler placement; and definitive module ABI are **open design questions**, not settled decisions.

## 1. User-supplied constraints and motivations — ACCEPTED

- Extensive practical Linux NIC and storage driver experience confirms much repeated code across vendors/chipsets. Often differences involve register offsets, descriptor fields, initiation and IRQ details, but some devices require substantial special cases.
- A successful DSL describes device/chipset *families* in a few maintained lines, using prebuilt vertical patterns. An ambitious working target is **roughly 70–90% shared/generated implementation** for suitable conventional NICs; this is a hypothesis, not a verified statistic.
- Favor optimized, native Rust execution initially; never mandate JIT as a prerequisite for first hardware bring-up.
- Support modern multicore x86-64 and AArch64; preserve the kernel's Linux-compatible userspace ABI. Existing kernel features reported include SMP, per-CPU scheduling, VFS, PCI, DMA, IRQ, ELF userspace and other infrastructure (verify actual repo before coding).
- A fully statically linked driver roster is infeasible. Runtime discovery and loading from initramfs/filesystems is an architectural requirement.
- Original idea: distribute **hash-locked declarative driver source**, not architecture-specific binary objects; potentially compile/JIT it at load. This remains a live hypothesis, not a requirement to put a compiler in ring 0.
- Isolation matters, but conventional microkernel IPC/process-per-driver can be expensive, and CPU memory isolation by itself cannot prevent destructive hardware commands. Capability limits and IOMMU protection matter.
- Developer slogan: **“Most driver code never has to be written.”**

## 2. Evidence: open-source NIC comparison

This is a **qualitative source-level comparison**, not an exhaustive audited function-by-function diff, LOC census, or tested driver port. The source links below are primary Linux code. Avoid treating estimates as measurements.

### 2.1 DEC Tulip / 21x4x (`tulip`)

- Main path: [`drivers/net/ethernet/dec/tulip/tulip_core.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/dec/tulip/tulip_core.c); related code in the same directory (`interrupt.c`, `tulip.h`, media/PHY files).
- Demonstrates classic shared RX/TX descriptor rings, ownership handoff (`DescOwned`), `cur_tx`/`dirty_tx`, DMA map/unmap, wrap markers, producer completion handling, receive refill, CSR programming, IRQ handler.
- TX sequence in source: choose ring entry; DMA-map skb; write buffer pointer and flags; arrange interrupt frequency; set ownership last. Some code explicitly discusses ordering requirements.
- Variation hazards: multiple 21x4x/clones, media selection, EEPROM, MII and PHY behaviors, bus/interface legacy assumptions, peculiar reset and setup-frame handling.
- **HADL potential:** `legacy_ownership_ring`, descriptors with owner/wrap/end flags, `tx_submit`, `rx_refill`, `irq_status_ack`, register map, small state machines. **Not** just offsets: Tulip's media/PHY logic illustrates hard exceptions.

### 2.2 Intel e1000e

- Main path: [`drivers/net/ethernet/intel/e1000e/netdev.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/e1000e/netdev.c), plus related MAC, PHY, NVM and hardware files.
- Explicit register families for RX and TX base address, length, head and tail (`RDBAL/RDBAH/RDLEN/RDH/RDT` and `TDBAL/TDBAH/TDLEN/TDH/TDT`).
- RX replenish (`e1000_alloc_rx_buffers`), descriptor-done handling (`e1000_clean_rx_irq`), TX completion/reclaim, DMA map/unmap, conditional batching of tail writes, DMA barriers, NAPI-like bounded processing.
- Multiple descriptor formats: legacy, extended context/data, packet-split RX; checksum and timestamp offloads. This argues for **tagged descriptor variants**, not one universal packet descriptor.
- Nontrivial exception: `__ew32_prepare`, `e1000e_update_rdt_wa`, `e1000e_update_tdt_wa` work around management-engine/firmware interactions and can check register writebacks and trigger resets. This must be modeled via explicit access protocols/quirks, not hidden in a generic raw MMIO accessor.
- **HADL potential:** `head_tail_ring`, specialized descriptor codec, completion and batching policy; unique MAC/PHY/ME subsystem and errata adapters.

### 2.3 Realtek r8169 family

- Main path: [`drivers/net/ethernet/realtek/r8169_main.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/realtek/r8169_main.c), hardware PHY support and firmware/variant code.
- Descriptor arrays and ring accounting, owner/first/last/end-of-ring flags, RX refill, TX DMA submission, completion/reclaim, IRQ masking/acknowledgment, polling.
- Extensive chipset revisions, different MAC and PHY versions, firmware loading, internal PHY interactions, nonuniform register programming, tuning workarounds and chip-specific start sequences.
- **HADL potential:** shared `ownership_ring` core plus `register-script/state-machine` init; revision selectors and reusable quirk definitions. Beware an exploding number of special cases and undocumented magic register writes.

### 2.4 Intel igc (I225/I226, more modern)

- Main path: [`drivers/net/ethernet/intel/igc/igc_main.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/igc/igc_main.c) and [`igc_base.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/igc/igc_base.c).
- Multiple RX/TX rings, queue vectors, MSI-X/interrupt moderation, NAPI polling, ring-index head/tail and doorbells, DMA and descriptor completion.
- Modern features make the ABI richer: XDP/AF_XDP, timestamps/PTP, filtering, traffic shaping, offloads. These should be **optional composable extensions**, not mandatory first-version DSL facilities.
- Explicit reset sequence in `igc_base.c`: stop PCIe master, mask interrupts, disable RX/TX, delay, set global reset and wait for completion. Strong candidate for a declarative **bounded state machine with ordering, timeout, and side effects**.
- **HADL potential:** `multiqueue_head_tail`, queue-to-vector mapping, interrupt moderation policy, per-queue instances, optional feature modules.

### 2.5 Observed shared pattern vs significant differences

| Component | Shared across studied drivers | Variations HADL must express |
|---|---|---|
| PCI matching and BARs | Probe, map MMIO, negotiate DMA | IDs/revisions, BAR mapping, supported DMA mask |
| TX ring | Acquire slot, map buffer, populate descriptor, publish ownership, notify hardware | Wrap vs indexed tail, descriptor variant, completion rule, multiple-fragment scatter/gather |
| RX ring | Allocate/map buffers, post to hardware, test completion, recycle/refill | Owner flags vs DD bits, packet-spanning descriptors, page split, alignment |
| DMA | Map/unmap, sync, ownership lifetime | 32 vs 64 bit, coherent vs streaming, cache/ordering, buffer size |
| IRQ | Acknowledge/mask, schedule poll, re-enable | MSI/MSI-X/INTx, acknowledge semantics, queue-vector maps, shared IRQ behavior |
| Polling | Drain bounded work, report completions, replenish | Budget accounting, TX/RX coordination, adaptive moderation |
| Lifecycle | Reset, wait-ready, configure, start, quiesce | PHY/NVM firmware, timing, clocking, errata, ownership with embedded controller |
| Management | Link state, stats, config, ethtool-like options | PHY/MDIO, EEPROM/NVM, autonegotiation, filters, offloads |

### 2.6 Preliminary pattern taxonomy — candidate, NOT validated exhaustive set

1. **Owner-bit circular ring:** HW/SW ownership toggles in descriptor flags (Tulip, Realtek style).
2. **Indexed head/tail circular ring:** CPU publishes producer via tail doorbell; hardware reports completion via status and/or head (e1000e/igc style).
3. **Descriptor phase/generation ring:** generation bits to disambiguate wrapped producer/consumer (common in newer queue protocols; research separate examples).
4. **Scatter/gather descriptor chain:** one logical packet/request consumes multiple descriptors, explicit SOP/EOP/segment count.
5. **Context/data descriptor pairing:** optional per-packet context entries for checksum, TSO, VLAN, etc.
6. **Interrupt-to-budgeted-poll:** mask/suppress interrupts, run per-queue budget, rearm safely without lost wakeups.
7. **Completion/IRQ coalescing:** periodically request interrupts or configure moderation.
8. **Reset/bring-up state machine:** bounded register operations, polls and delays, explicit error transitions.
9. **PHY/NVM/firmware transaction engine:** indirect register windows, MDIO, serial EEPROM, firmware protocol (could be a separate sub-DSL).
10. **Revision and erratum overlays:** narrow matching predicate + revised access, sequencing, or capability flags.

**Major finding:** Ring ownership, descriptor codecs, DMA lifetime, polling and initialization form a compact vocabulary. But treating all differences as `register offset` would fail; ring protocol, descriptor states, reset ordering, silicon revisions and errata are first-class semantics.

## 3. Proposed HADL language architecture — ACCEPTED IN PRINCIPLE, grammar OPEN

HADL is a *semantic* hardware DSL. It describes **what operations mean**, not merely where bits live.

Minimum conceptual declarations:

- `device`: PCI vendor/device/class/revision/subsystem match, compatibility and priority.
- `bar` / `register`: region, access width, offset, array stride, fields, access mode (RO/RW/W1C/read-clear), side effects, legal states, flush/readback rules.
- `descriptor`: fixed layout, endian/alignment, tagged format variants, DMA address fields, ownership, length, SOP/EOP, completion/error decode.
- `queue`: ring/linked-list type, size constraints, producer/consumer roles, memory ordering, doorbell action and wrap policy, queue concurrency owner.
- `interrupt`: MSI-X/MSI/INTx, cause registers, acknowledge semantics, masking and re-enable protocols, mapping to queues.
- `lifecycle`: bounded reset/init/start/stop/suspend/resume/recovery transitions; timeouts, polls, delayed actions.
- `vertical`: `ethernet_dma`, `nvme_multiqueue`, `ahci_slots`, etc., each backed by a tested Rust engine.
- `variant` / `quirk`: revision predicates and localized overrides with explicit provenance.
- `capability`: IOMMU, DMA width, MMIO access, DMA memory budget, IRQ vectors, firmware requirements, prohibited privileged actions.

Example **illustrative pseudocode; not a real PCI chipset nor stable grammar**:

```text
device sample_nic {
    pci { vendor: 0x1234; device: 0x5678; }
    bar 0 { type: mmio;
        register TX_TAIL at 0x2000: u32 {
            access: write_only; effect: tx_doorbell;
            valid: value < tx.queue_size;
        }
        register IRQ_CAUSE at 0x0200: u32 { access: write_one_to_clear; }
    }
    dma descriptor TxDesc { align: 16; endian: little;
        addr: u64; length: u16; flags: u16;
        owned_by_hardware: flags.bit(15);
    }
    queue tx { pattern: owner_bit_ring; descriptor: TxDesc;
        producer: driver; consumer: hardware; notify: TX_TAIL;
    }
    interrupt { pattern: mask_poll_rearm; cause: IRQ_CAUSE; }
    network { engine: ethernet_dma; tx_queue: tx; }
}
```

**Critical implementation caution:** A compiler-checked register constraint is enforceable if the executing code cannot bypass the checked accessor. A compartment given unrestricted MMIO mapping can still write any mapped register; text in a manifest does not create physical hardware enforcement. Safe Rust APIs, restricted bytecode and mediation have different trust assumptions.

## 4. Design alternatives and status — KEEP ALL, INCLUDING DEPRIORITIZED

| Design | Status | Strength | Weakness / rationale |
|---|---|---|---|
| Handwritten low-level native Rust built into kernel | **ACCEPTED as bootstrap** | Fastest to bring up, straightforward debugging | Scaling by statically linking every chipset violates requirement; repetition |
| Native Rust dynamically loaded ELF modules | **RETAIN as fallback** | Handles devices outside DSL, familiar mechanics | Native kernel memory exposure; ELF relocations, dependencies, unload, cross-version ABI |
| HADL → generated Rust → statically compiled | **RECOMMENDED first experiment** | Fast development, normal Rust toolchain, optimized baseline | Does *not* alone satisfy dynamic loading |
| HADL → generated Rust → loadable native ELF | **VALID alternative** | Runtime loading, optimized native code | Kernel ABI compatibility and relocation management, architecture-specific binaries |
| HADL source distributed, compiled by **userspace** on installation/first use | **PROMISING OPEN OPTION** | Hash-locked audited source, dynamic support, small kernel TCB | Requires userspace compiler and bootstrapping/cache workflow |
| HADL source parsed and compiled **inside kernel** | **DEPRIORITIZED, not eliminated** | Single package format, autonomous loading | Parser/typechecker/codegen/JIT in trusted kernel, memory and attack surface |
| HADL → compact typed IR / data package → generic native Rust engines | **PREFERRED eventual runtime path, pending measurement** | Architecture-neutral, small loadable artifact; no per-device ELF required | Indirections and semantic engine coverage; versioning |
| HADL → bytecode → verifier → native JIT | **RETAIN for later research** | Portable, specialization, potentially verifiable operations | Complex verifier/JIT, arbitrary long-lived driver semantics, soundness concerns |
| HADL → Wasm or eBPF backend | **RESEARCH OPTION** | Existing portable bytecode ideas/tools | Neither is naturally a complete device DSL; host APIs and hardware safety remain |
| Isolated userspace driver processes (seL4/Redox model) | **CONSIDERED; not primary default** | Fault containment; MMU/IOMMU | Context/IPC cost and synchronization; hardware destructive authority persists |
| VMX/SVM/EL2 driver compartments | **LONG-TERM RESEARCH** | Strong CPU memory isolation with native driver code | VM exits, complex scheduling/interrupts, IOMMU topology, recovery |
| Memory protection keys / lightweight in-kernel compartments | **RESEARCH OPTION** | Cheap compartment switching in some settings | Not sufficient to constrain privileged instructions; platform-specific and subtle |
| Kernel as control plane / asynchronous I/O engines | **ENDORSED ARCHITECTURAL PATTERN** | Per-queue ownership, batching, lock avoidance, high SMP throughput | Communication model, not itself an isolation model |
| Device specifications generate mediated access policies | **PROMISING RESEARCH** | Semantics, documentation and safety checks from one source | Raw hardware access can bypass software rules |
| Fully synthesized arbitrary driver from formal device specification (Termite-style) | **RESEARCH, not MVP** | Potential maximal automation | Specification fidelity, complex hardware protocol and synthesis complexity |

**Important conceptual distinction:** Driver *authoring language* (Rust vs HADL), *distribution artifact* (source/IR/ELF), *loading mechanism* (data instantiation/JIT/relocation), *execution location* (kernel/userspace/VM compartment), and *hardware authority* (raw or mediated MMIO/DMA) are separate axes. Do not collapse them into one binary monolithic-vs-microkernel choice.

## 5. Dynamic loading: actual requirement and proposed resolution

**Required:** New driver/chipset descriptions install and load at runtime without rebuilding/booting a new kernel image, subject to supported engine APIs and necessary bootstrap functionality.

**Preferred initial implementation:**

1. A minimal built-in PCI/IRQ/DMA/kernel-driver engine manager discovers a device.
2. A driver registry matches a versioned device-ID/revision manifest.
3. A small binary data package is loaded from initramfs or filesystem (no native code generated for ordinary register/descriptor descriptions).
4. Kernel validates bounds/field layouts, descriptor constraints, queue limits, permitted access transitions, resource claims and schema version; rejects ambiguous/invalid packages.
5. A generic Rust engine instance is configured from the immutable description, allocated hardware resources and started.
6. For exceptional logic, use a declared narrow escape hook, initially compiled native Rust; later consider bounded executable IR.
7. Reference count package, device, queues, DMA mappings and interrupts; unload only after interrupt quiescence, DMA fencing/reset, work draining and outstanding references are gone.

**Bootstrap caveat:** Drivers needed to read the package filesystem must be built in, present in initramfs, or obtainable through a working early-boot path. Do not assume dynamic loading solves its own storage dependency.

**ABI policy:** Avoid arbitrary Rust ABI across compiler versions. Rust native ABI is not stable. Native modules should expose a narrow, versioned, `extern "C"`/`#[repr(C)]` interface with opaque handles and callback tables, and bind against a minimum kernel API. HADL packages should reference semantic engine operations, not internal Rust symbols. Specify compatibility, revocation, unwind/panic policy, relocation validation and W^X executable mapping if native modules are implemented.

**Source identity:** Hash a canonical, versioned package including all included files, imports, engine/schema constraints and optional firmware references; optionally sign it. A content hash proves identity, a signature attests publisher/authorization, and a verifier checks safety. These are not interchangeable. Firmware may have separate hashes and rights.

## 6. Performance and multicore rules

- Shared Rust engines should specialize descriptor access, ring size, field masks, offsets, ownership semantics, endian conversions and MMIO addresses wherever possible.
- AOT/generated Rust should be the baseline against which a data-driven engine and eventual JIT are benchmarked; do not assume JIT is superior.
- For multiqueue NICs, prefer one logical software owner per RX/TX queue (or carefully chosen producer/consumer model); exploit per-CPU queues, lock-free SPSC where applicable, batched completions and doorbells.
- Specify DMA barriers (`dma_wmb`/`dma_rmb`-equivalent), coherent/streaming mapping semantics, MMIO ordering, publish/consume visibility, cache sync on noncoherent AArch64, and explicit ownership transfers. `volatile` alone is insufficient synchronization.
- Keep hot-path data structures cacheline-aware. Compare throughput, packets/sec, cycles/packet, p50/p99/p99.9 latency, cache misses, IRQ rate, and CPU utilization under polling vs interrupts.
- A driver engine consuming a description may incur extra loads and branches; measure whether const specialization, initialization-time resolution, or JIT is needed. This is **an open question**.

## 7. Security and fault model

Three different failure boundaries:

1. **CPU memory:** MMU address spaces, EPT/NPT/Stage-2, or verified code might protect host memory from driver CPU accesses.
2. **Device DMA:** IOMMU/SMMU domains and PCIe topology determine which physical pages a device can access. Linux VFIO group constraints illustrate that device-level isolation is not universally available.
3. **Physical device behavior:** A valid register write can erase storage, reset hardware, hang firmware or disrupt other functions. Memory isolation cannot universally prevent this.

Therefore, classify access by authority: register and doorbell direct access for vetted operations; kernel mediated reset, firmware changes, PCI config, DMA domain management and other dangerous actions. Typed DMA handles must not permit arbitrary physical address fabrication. Keep pin/map/unmap lifetimes and buffer revocation explicit. Device recovery is only safe if bus-master/DMA access is demonstrably fenced; controller reset may affect other functions or be impossible.

For verified bytecode, bound each event handler invocation even if device lifetime is indefinite. Driver scheduling, interrupts, callbacks and fault state across SMP need defined state transitions (`Running → Quiescing → Revoking → Resetting → Restart/Failed`). Rust memory safety does not guarantee safe hardware behavior. Verified code is only as safe as its verifier/JIT and host capability helpers.

## 8. Concrete experiment and acceptance tests

### Phase A — Source archaeology and pattern proof

- Inspect actual functions and data layouts in Tulip, e1000e, r8169 and igc sources. Build a matrix of concrete descriptors, ownership semantics, ring conventions, BAR/register protocols, IRQ paths, init/PHY/NVM/firmware and error handling.
- Record each pattern's exact source symbols, chipset match, variants and dependencies. Distinguish *same algorithm* from superficial syntactic similarity.
- Independently inventory lines of maintained code in shared engine, description, exceptions, DSL compiler and runtime. Track complexity as well as lines.
- **Exit:** At least two independent NIC families can be expressed using the same core ring/IRQ/DMA patterns with explicit, bounded exceptions.

### Phase B — Small engine and compiler

- Implement a constrained HADL parser/schema and static semantic checker outside the kernel. Start with typed register maps, descriptors, basic queues, reset scripts and interrupt semantics.
- Generate readable Rust accessors/adapters and integrate with one `no_std` Rust engine. Require deterministic output from canonical descriptions.
- Keep an independent test emulator for descriptor ring hardware and fault-inject completion/wrap/timeout behavior; run host unit tests before real hardware.
- **Exit:** TX and RX in QEMU or physical test NIC, including exhausting full rings, wrap-around, fragmented descriptors when supported, checksum/offload disabled initially, and error/recovery tests.

### Phase C — Dynamic data package

- Freeze a narrow versioned binary schema (or typed canonical IR encoding), implement bounded parser and type/semantic validation within kernel, engine registration and PCI matching.
- Load same package from initramfs after boot; unload/reload without kernel relink. Negative tests: malformed offsets, out-of-range fields, conflicting IDs, untrusted package hashes, unsupported engine revision, invalid DMA width.
- **Exit:** Runtime install/load/unload of a new supported chipset description without rebuilding kernel. Existing devices remain operational through failures.

### Phase D — Demonstrate cross-vendor reduction

- Port second and third independent NIC. Prefer **Tulip/e1000e/r8169** for diverse classic designs, then **igc** for multiqueue and modern features. Tulip is historically interesting but old hardware; use QEMU/available hardware for practical coverage.
- Track `maintained_total_loc = shared_engines + DSL_toolchain + package_loader + chipset_specs + handwritten_escapes`, not only chipset-spec LOC. Report incremental LOC per added chipset separately.
- Suggested *ambitious acceptance target*, not empirical forecast: ~200–500 maintained chipset-specific lines for ordinary Ethernet baseline; investigate failures objectively rather than twisting DSL to meet an arbitrary count.
- **Exit:** Three genuinely different NIC families run equivalent network traffic through shared engine and no unacceptable regression compared with native implementation.

### Phase E — Optional executable IR / JIT / isolation

- Benchmark data-driven engine versus generated-Rust AOT before adding a JIT; instrument CPU cycles per packet and tail latency.
- If justified, add typed operations for exceptional state machines with a small verifier and native backend; disallow arbitrary pointers, syscalls and privileged instructions except capabilities.
- Explore isolated userspace or VMX/EL2 execution on hardware with IOMMU; compare fault containment and throughput against baseline. Keep hardware authority independent of CPU execution placement.

## 9. Open engineering questions for owner/agent

1. Is HADL primarily **declarative data**, or must it express conditional loops/functions? Strong preference: data plus bounded transitions and explicitly scoped Rust escape functions.
2. Ship **canonical source**, **canonical binary IR**, or both? Proposed: source for review and distribution, compiled package for kernel ingestion; content-address and cross-link both.
3. What is the stable engine API/versioning contract? How are optional features negotiated and mismatches rejected?
4. Can device families share one engine while differences stay comprehensible, or do pattern variants proliferate beyond saving LOC?
5. Which NIC hardware is currently available to run end-to-end tests? e1000 QEMU, physical Realtek, modern igc, Tulip emulation?
6. Must a native ELF loadable module be untrusted, or is it explicitly **trusted fallback** pending hardware compartments? Recommend the latter until real isolation is implemented.
7. How does a module reference kernel data and callbacks without native Rust ABI dependencies, and how is unload made safe across IRQ/DMA/SMP?
8. Are driver descriptions expected to support architecture-independent DMA/MMIO endian and coherency semantics transparently? Recommend yes.
9. How are chip-specific firmware and redistributability/license restrictions represented? A hash manifest alone does not supply firmware.
10. Can an eventual hardware vendor produce a HADL description from silicon documentation/SystemRDL, allowing review rather than rewrite? Long-term vision, not MVP.

## 10. Prior art to study (primary references)

- [Linux Tulip driver](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/dec/tulip/tulip_core.c)
- [Linux e1000e](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/e1000e/netdev.c)
- [Linux r8169](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/realtek/r8169_main.c)
- [Linux igc](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/igc/igc_main.c); [igc reset/base](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/igc/igc_base.c)
- [Devil hardware IDL, OSDI 2000](https://www.usenix.org/legacy/events/osdi2000/full_papers/merillon/merillon_html/index.html)
- [HAIL: Hardware Access Interface Language](https://junsun.net/publications/SuWaKaIs05.pdf)
- [Termite / Numbat automatic driver synthesis research](https://trustworthy.systems/projects/OLD/drivers/synthesis/)
- [SystemRDL](https://www.accellera.org/activities/working-groups/systemrdl)
- [svd2rust](https://github.com/rust-embedded/svd2rust) / [CMSIS SVD register semantics](https://open-cmsis-pack.github.io/svd-spec/main/elem_registers.html)
- [seL4 user drivers and DMA caveats](https://docs.sel4.systems/projects/sel4/frequently-asked-questions)
- [L4Re performance](https://www.l4re.org/performance.html)
- [Arrakis: OS as Control Plane](https://www.usenix.org/conference/atc15/technical-session/presentation/peter)
- [Dune: VT-x process-level use](https://mast.stanford.edu/pubs/dune/)
- [Lightweight Kernel Isolation with Virtualization and VM Functions](https://conf.researchr.org/details/vee-2020/vee-2020-papers/14/Lightweight-Kernel-Isolation-with-Virtualization-and-VM-Functions)
- [Linux VFIO IOMMU isolation](https://docs.kernel.org/driver-api/vfio.html)
- [Linux eBPF verifier](https://docs.kernel.org/bpf/verifier.html)
- [Linux module signing](https://docs.kernel.org/admin-guide/module-signing.html)
- [Rust ABI and external blocks](https://doc.rust-lang.org/reference/items/external-blocks.html)
- [WebAssembly core spec](https://www.w3.org/TR/wasm-core/)

## 11. Explicit instruction to future coding agent

Do **not** interpret this document as authorization to rewrite the existing driver infrastructure wholesale. First inspect actual kernel source, tests and hardware support, then propose a scoped prototype and verify prerequisites. Preserve existing operational paths. A prototype should emphasize **one pattern library and two cross-vendor NICs**, a compact description format, explicit DMA/IRQ invariants, and quantitative maintained-LOC/performance measurements. Keep unselected theories visible as research branches; do not silently promote hypotheses into accepted requirements.


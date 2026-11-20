# hk: a Rust API for IRQ and DMA drivers

Research, 2026-11. The goal is the driver API hk wants before many DMA-ring
drivers land: Ethernet MACs and PHYs, AHCI, NVMe, more xHCI. It must serve
two aims. (1) README's "modern, highly multi-core" machines: per-CPU queues,
one MSI-X vector per queue, NAPI-style polling, completions that take few
locks. (2) The least code per driver (`hk-hadl-prep.md`). This note gives
concrete shapes for ROADMAP M4 (typed DMA and MMIO), for D's MSI work and
for the HADL vocabulary and engine (`hk-hadl-prep.md` H1–H3). It refines
those plans and does not replace them. Everything here is a proposal, and
every LOC figure is a rough estimate.

## 1. Evidence: what our drivers repeat

Code lines below exclude comments and blank lines. Measured: e1000 646,
virtio-net 418, virtio-blk 599, virtio-pci 615, the xHCI files
(`xhci.rs`, `xhci_ring.rs`, `transfer.rs`, `context.rs`) 3238.

| # | Pattern | Where | ~Lines |
|---|---|---|---|
| 1 | Registers as bare consts plus wrappers; access semantics only in comments (ICR clears on read, IMC/IMS are write-only, USBSTS/PORTSC are W1C) | `hw/net/e1000.rs` `reg`/`ctrl`/`int` mods, `E1000::read_reg`/`write_reg`/`read_mac`; `hw/usb/xhci.rs` `op`/`usbcmd`/`usbsts`/`portsc`/`ir` mods, `Xhci::read_op`/`read_port`/`write_port`, `portsc::to_neutral` (a W1C mask coded by hand); `hw/virtio/pci.rs` `r8`..`w64` | 170 |
| 2 | Bitfield setters for hardware structs | `hw/usb/context.rs` `SlotContext`/`EndpointContext`/`InputControlContext` `set_*`/`get_*`; `hw/usb/transfer.rs` `Trb` `set_*`/`get_*`/constructors; e1000 `RxDesc`/`TxDesc` with `rxd_stat`/`txd_cmd` | 410 |
| 3 | Field-by-field `write_volatile(&raw mut (*d).f)` into DMA memory, with the publish-last barrier placed by hand | e1000 `transmit`/`receive`/`init_rx`/`init_tx`/`TxRing::reclaim`; xHCI `CommandRing::enqueue`/`noop_at`, `EventRing::dequeue`, `TransferRing::raw_put`; `Vring::publish`; virtio-blk `write_hdr`. There are about 75 volatile sites and 25 barriers in hw/net, hw/usb and hw/virtio. `InputContext::slot_mut`/`endpoint_mut`/`control_mut` hand out `&mut` into DMA memory (breaks doc/UNSAFE.md rule 8) | 150 |
| 4 | Ring index and ownership models, each coded again | head/tail: e1000 `TxRing`/`RxRing` (TDT/RDT); cycle bit three times: `CommandRing`, `EventRing`, `TransferRing`; avail/used: `Vring`. `EventRing` and the e1000 rings have no host tests | 750 |
| 5 | Carving one coherent block into slots, and free-slot stacks | virtio-net `Pool::cpu`/`dma`, `TxQueue.free`; virtio-blk `VbQueue::hdr_dma`/`status`, `VbQueue.free`; e1000 `alloc_bufs` allocates one coherent block per 2 KiB buffer, so each uses a 4 KiB frame (`DirectDmaOps::alloc_coherent`): 192 frames per device, half of each unused; xHCI `XhciMem::frame` skips the DMA API entirely (phys = bus address) | 90 |
| 6 | DMA lifetime handled by hand: `DmaCoherent` has no `Drop`, so every remove frees after reset, and error paths leak | e1000 `free_rings`; virtio-net `VirtioNetWrapper::remove`; virtio-blk `stop`; `VirtioDevice::del_vqs` | 70 |
| 7 | Interrupt plumbing per transport | virtio-pci `IrqSlot` state machine + `alloc_vectors`/`queue_vector`/`request_msix`/`request_intx`; `hw/pci/msix.rs` `MsixVectors` (its only user); virtio-blk `vectors` + `first_cpu`; INTx-only e1000 and xHCI; the INTx "reap every queue" fallback (`VirtioBlk::vq_interrupt(None)`) | 300 |
| 8 | The NAPI skeleton, twice | e1000 and virtio-net `NapiPoll::poll`, `rearm`, `mask`, `NetDeviceOps::open`/`stop`, `napi_off` bookkeeping (as `hk-hadl-prep.md` §1 notes) | 2 × 150 |
| 9 | Probe/remove ceremony | `try_box(MaybeUninit<Wrapper>)`; a wrapper struct implementing `base::Bound` (`as_any`, a stats printk in `shutdown`, an ordered `remove`: unregister, `napi_disable` unless `napi_off`, reset, drop IRQ, `netif_napi_del`, free rings); unwinding written out with `inspect_err`/`match` | 3 × 100 |

Patterns 1–9 make up about 430 of e1000's 646 lines and about 300 of
virtio-net's 418. Chip-specific logic is the remainder: the MAC filter, link
status, the virtio feature bits.

Bugs these patterns caused (found here, not fixed; they belong in BUGS.md):
- virtio-net `setup_queues` leaks the RX virtqueue and pool when the TX side
  fails. `VirtioNetDriver::probe` leaks the queues and the NAPI
  registration when `try_arc` or `request_irq` fails.

These are leaks, not use-after-free: leaked memory the device may still
write is never reused.

Soundness gap: `DmaBox`'s drop is safe code, yet it is correct only if the
device has stopped using the memory. Today the driver vouches for that
(the `DmaBox` doc says so). Under doc/UNSAFE.md rule 4 a safe fn that can
cause UB is a bug. Proposal B closes the gap.

`IoMem`'s invariant says "hk never unmaps an ioremap", yet `XhciMem::drop`
calls `iounmap`. Because `IoMem` is `Copy`, the SAFETY claim that "every
register window is gone" cannot be checked.

## 2. What others do

- **Linux.** Managed resources: `pcim_enable_device`, `pcim_iomap_regions`,
  `devm_request_irq`, `dmam_alloc_coherent`, all unwound in reverse by the
  devres list. `dma_pool` provides small descriptors and `page_pool`
  provides recycled RX pages. Queues follow the interrupts:
  `pci_alloc_irq_vectors_affinity` + `blk_mq_map_hw_queues`.
  - igb's `q_vector` is one NAPI plus one MSI-X vector per rx/tx ring
    pair. `igb_alloc_q_vector` alone is about 130 lines and igb's
    setup/free/request-IRQ helpers about 300.
  - NVMe's `nvme_queue` is a coherent SQ and CQ, a phase bit and one
    vector per queue (`nvme_alloc_queue`, `nvme_poll_cq`).
  - regmap access tables mark registers volatile or precious (precious
    means a read clears them). `readx_poll_timeout` covers polled waits.
- **Rust-for-Linux** (`~/tmp/repo/linux/rust/kernel/`):
  - `io/register.rs` `register!`: a typed register with bitfields, arrays
    and relative bases.
  - `io.rs` `io_project!`/`io_read!`/`io_write!`: one field-projection
    syntax over both `Mmio` and `dma::CoherentView`, the same vocabulary
    for MMIO and DMA memory.
  - `dma.rs` `Coherent<T>`/`CoherentBox`.
  - `devres.rs`/`revocable.rs` `Devres<T>`: resources die at unbind.
  - `irq/request.rs` `Registration` takes an `IrqRequest<'a>` tied to
    `Device<Bound>`; `pci/irq.rs` allocates vectors; `io/poll.rs` has
    `read_poll_timeout`.
- **Tock** `register_bitfields!`/`register_structs!`: `ReadOnly`/
  `WriteOnly`/`ReadWrite` types, `LocalRegisterCopy`.
- **embassy** (chiptool/svd2rust PACs): register blocks generated from
  descriptions; `bind_interrupts!` binds handler types to IRQs at compile
  time.
- **Theseus** `nic_queues` + `intel_ethernet`: `RxDescriptor`/
  `TxDescriptor` traits that e1000 and ixgbe share, and a generic
  `RxQueue<D>`. This is the closest precedent for a shared ring model.
- **Redox** `Dma<T>` derefs to `&T` over device-written memory, the shape
  hk must avoid.
- **Asterinas OSTD** `DmaCoherent`/`DmaStream` with `VmReader`/
  `VmWriter`: no references into DMA memory, and unsafe confined to the
  framework.

They converge on three ideas: (1) one field vocabulary for MMIO and DMA
memory; (2) resources owned by the bound device and released in reverse;
(3) a queue is a vector plus a ring plus a poll context, placed on a CPU.
One proposal follows for each.

## 3. Proposal A: one layout vocabulary for registers and descriptors

**Problem.** Patterns 1–3: about 730 lines in e1000 and xHCI, most of the
drivers' `unsafe` (e1000 13 blocks, `context.rs` 6, xHCI's volatile
sites), and access rules that live only in comments.

**API** (`hw/io/`; `macro_rules!` only, so no proc-macro crate and no
new packages):

```rust
/// A bitfield value type: getters, `with_*` setters, consts
bitfield! {
    pub struct Portsc(u32) {
        0      ccs: bool;
        1      ped: bool  [w1c];
        9      pp:  bool;
        13:10  speed: u8;
        17     csc: bool  [w1c];
        // ...
    }
}

/// A register block over any `R: RegIo` (IoMem; MockRegs in host tests;
/// a tracing backend for the planned mmiotrace feature)
regs! {
    pub struct E1000Regs {
        0x0000 ctrl:   Rw<Ctrl>,
        0x0008 status: Ro<Status>,
        0x00c0 icr:    Rc<Int>,        // read clears: no modify()
        0x00d0 ims:    Wo<Int>,
        0x00d8 imc:    Wo<Int>,
        0x2800 rdba:   Rw64Split,       // lo/hi pair, lo first
        0x2818 rdt:    Db<u32>,         // doorbell: ordered after DMA writes
        0x5200 mta:    [Rw<u32>; 128, stride 4],
        0xc018 rdt_q:  [Db<u32>; 16, stride 0x40],  // igb per-queue
    }
}

/// A descriptor or context in DMA memory: a Pod value type and a view
/// type whose accessors are volatile and whose offsets are checked by a
/// const assert. The `owner` field is written last on publish and read
/// first on consume.
dma_struct! {
    #[size = 16]
    pub struct RxDesc {
        0  addr:   Le64,
        8  len:    Le16,
        12 status: RxStat [owner],
        13 errors: u8,
    }
}

impl<'a, T: DmaStruct> DmaView<'a, T> {
    pub fn read(self) -> T;                  // whole value, volatile
    pub fn publish(self, v: T);              // other fields, dma_wmb, owner field
    pub fn consume(self) -> Option<T>;       // owner field, dma_rmb, the rest
    // plus generated per-field get()/set()
}
```

- `Rc` has `read` only. `W1c` fields are masked to 0 in `modify`, so
  `portsc::to_neutral` becomes a property of the type.
- `Db` and plain `write` are ordered (Linux `writel`); `write_relaxed` is
  the explicit fast path (ROADMAP M4's "ordered IoMem writes plus
  `_relaxed`").
- `reg.wait(|s| s.lu(), timeout)` wraps `time::delay::poll_timeout`
  (hadl-prep's `wait_bits`). It replaces e1000's 100,000-iteration spin in
  `E1000::reset` and xHCI's `halt_regs`/`reset_regs` closures.

Fragment (e1000 ISR and RX):

```rust
fn irq_ack(&self) -> Option<Int> {
    let icr = self.r.icr().read();
    (!icr.is_empty()).then(|| { self.r.imc().write(Int::ALL); icr })
}
while let Some(d) = rx.ring.desc(rx.next).consume() { /* d.len.get() ... */ }
```

**LOC.**

| Driver | Before | After |
|---|---|---|
| e1000 (registers, bits, accessors, descriptors, volatile code) | 145 | 80 |
| xHCI (`context.rs` setters 200→70, `Trb` 180→60, register mods + accessors 85→55, volatile/fence code 25→8) | 490 | 190 |
| New igb-class NIC (register/descriptor layer) | 250 | 120 |

The vocabulary costs about 400 lines once, plus host tests.

**Locking.** Adds no locks. A register is lock-free from the type's view;
ordering between CPUs belongs to the owner's lock, as with `IoMem` today.
`Rc` and `W1c` registers are read in the ISR or under the owner's
IrqSpinlock only.

**Unsafe.** The `IoMem` and `DmaView` primitives keep the only `unsafe`.
Generated code has none, which removes field-level `unsafe` from drivers.
`DmaView<'a, T>` borrows its array (proposal B), so a view cannot outlive
the memory, and there is never a `&`/`&mut` into it.

**Per-CPU fit.** Register arrays with a stride give each queue its own
typed sub-window (`rdt_q(i)`), held in that queue's context. No shared
register state.

**Risks and open questions.**
- `macro_rules!` bit-range syntax is clumsy and its errors are poor. RfL
  accepted that in `register!`; a proc-macro would need syn/quote, which
  needs the owner's OK.
- Endianness: every target is little-endian, but keep `Le*` types for
  virtio, NVMe and xHCI clarity.
- Should `IoMem` become a non-`Copy` owned `IoRegion` (unmapped on drop)
  handing out borrowed windows, or stay "never unmapped"? xHCI's
  `XhciMem` currently contradicts the invariant.

**Migration.**
1. `DmaView` + `dma_struct!` with e1000 descriptors (M4).
2. `regs!` on e1000.
3. xHCI contexts and `Trb` (the largest win).
4. The virtio common config.

## 4. Proposal B: device-owned DMA memory and ring models

**Problem.** Patterns 4–6: about 900 lines of rings, carving and frees;
leaks on error paths; the `DmaBox` soundness gap.

**API** (`hw/dma/`):

```rust
/// What a bound device was given (Linux devres for dmam_*, RfL Devres):
/// made in probe, fenced at unbind
pub struct DmaScope { /* Arc<inner>: DmaConfig, ops, limbo list, fenced */ }

impl DmaScope {
    pub fn new(pci: &PciDevice) -> KernelResult<Self>;      // enables bus mastering
    pub fn array<T: DmaStruct>(&self, n: usize) -> KernelResult<DmaArray<T>>;
    pub fn slab<T: DmaStruct>(&self, n: usize) -> KernelResult<DmaSlab<T>>;
    /// Bus mastering off, flushed by a config read; then frees limbo
    /// (thread context; Linux pci_disable_device)
    pub fn fence(&self);
}

/// n typed elements of zeroed coherent memory
pub struct DmaArray<T> { /* scope ref, DmaCoherent */ }
impl<T: DmaStruct> DmaArray<T> {
    pub fn desc(&self, i: usize) -> DmaView<'_, T>;        // panics out of range
    pub fn dma(&self, i: usize) -> DmaAddr;
    /// Free now; `q` proves the device stopped using this memory
    pub fn release(self, q: &Quiesced);
}
// Drop without release: queued on the scope's limbo (intrusive, no
// allocation, IRQ-safe), freed at fence(). Leak-safe, never early.

/// Engine-minted proof that the device stopped using memory (virtio reset,
/// xHCI Disable Slot completion, NVMe Delete SQ/CQ)
pub struct Quiesced(());
impl Quiesced { pub unsafe fn new() -> Self; } // # Safety: device no longer addresses it

/// Many small elements from one coherent block, packed (fixes e1000's
/// one-frame-per-2KiB buffers; virtio-net Pool; virtio-blk header+status;
/// AHCI command tables)
pub struct DmaSlab<T> { /* DmaArray<T> + per-element offsets */ }

/// A free-slot stack with reserved capacity: push/pop never allocate
/// (virtio-blk free, virtio-net TxQueue.free, NVMe command ids)
pub struct Tags { /* KVec<u16> */ }

/// Streaming mapping, unmapped on drop (IRQ-safe, as dma_unmap_single)
pub struct DmaMap { /* addr, len, dir, scope ref */ }

/// Ring ownership models: who owns slot i, how the index wraps, what the
/// doorbell takes
pub trait RingModel { fn cpu_owns(&self, i: usize, d: &impl DmaStruct) -> bool; /* ... */ }
pub struct HeadTail;           // e1000/igb/ixgbe TX+RX, NVMe SQ: head register, tail doorbell
pub struct Phase { pcs: bool } // xHCI event ring, NVMe CQ: cycle/phase bit flips at wrap
pub struct PhaseLinked;        // xHCI command/transfer rings: Phase + Link TRB toggle
pub struct OwnerBit;           // RTL8168 DescOwn: the dma_struct! owner field

pub struct Ring<T: DmaStruct, M: RingModel> { mem: DmaArray<T>, head: usize, tail: usize, m: M }
impl<T: DmaStruct, M: RingModel> Ring<T, M> {
    pub fn produce(&mut self, v: T) -> Result<usize, Full>;   // publish() inside
    pub fn consume(&mut self) -> Option<(usize, T)>;          // consume() inside
    pub fn doorbell(&self) -> u32;
}
```

The virtio split ring stays its own model (`Vring`, already factored and
tested). xHCI's growing `TransferRing::expand` stays a specialization over
`PhaseLinked` segments.

Fragment (e1000 TX on `Ring`, with bounce buffers from a slab):

```rust
let i = tx.ring.produce_with(|i| { tx.bufs.copy_in(i, skb.data()); TxDesc::eop(tx.bufs.dma(i), len) })?;
self.r.tdt().write(tx.ring.doorbell());
```

**LOC.**

| Driver | Before | After |
|---|---|---|
| e1000 (rings, `init_rx`/`init_tx`, `free_rings`, `alloc_bufs`, probe allocations, ring parts of `transmit`/`receive`) | 200 | 70 |
| virtio-net pools, free lists, frees | 45 | 10 |
| virtio-blk pool carving and `stop` | 45 | 12 |
| xHCI (`CommandRing`/`EventRing` 138, `XhciMem`, the shared part of `TransferRing`) | 470 | 250 |
| New NVMe queue management (Linux `nvme_alloc_queue`/`nvme_free_queue`/CQ walk/doorbells/`nvme_sq_copy_cmd`, about 120 lines plus teardown) | 120 | 40 |

The library costs about 450 lines (scope 120, slab/tags 80, models 250),
host-tested on the existing `Fake` and `for_test` patterns.

**Locking.**
- A `Ring` has no lock of its own: it lives under its queue's lock (the
  `spin::Mutex` queue context in C, or the blk-mq hctx `IrqSpinlock`).
- `DmaScope` limbo is an `IrqSpinlock` leaf with intrusive push, so a drop
  under `Xhci.lock` or in hardirq is fine. `fence` runs in thread context
  only (it frees frames).
- This needs a new LOCKING.md row in 3.10 "DMA API".

**Unsafe.**
- All memory is owned. Views borrow it (rule 8).
- Early free needs a `Quiesced`, minted by one `unsafe` call per engine at
  the protocol point that proves quiescence.
- Every other free waits for bus mastering off. That makes `DmaBox`'s
  drop sound (rule 4) and turns error-path leaks into fenced frees.
- `DmaBox` becomes `DmaArray<[u8; N]>` or stays as the untyped form.

**Per-CPU fit.** One `Ring`, `DmaArray` and `Tags` per hardware queue, no
global pool. Later: allocate each on the queue CPU's node
(`alloc_coherent` with a node). Pages recycled by the planned
`page_pool` come from a per-RX-queue pool on the same scope.

**Risks and open questions.**
- Is bus master disable a valid fence for every target? Linux relies on it
  in `pci_disable_device`. Shared or SR-IOV functions and the IOMMU later
  make the scope a DMA domain.
- Limbo memory grows on long-lived devices that churn objects (xHCI slot
  rings across hotplug), so every such engine must mint `Quiesced` where
  its protocol allows.
- How the typed `DmaAddr` (private constructor, M4) and `DmaView`
  interact with `Pod`/`util/pod.rs`.

**Migration.**
1. `DmaScope`/`DmaArray`/`DmaSlab`, converting every `dma_free_coherent`
   user: e1000, virtio-net, virtio-blk, `VirtioDevice::del_vqs`,
   `Hcd::buffer_free`. This fixes the leaks above.
2. `Ring<HeadTail>` on e1000.
3. xHCI command, event and transfer rings through `DmaScope`
   (ROADMAP M4's "xHCI rings through the DMA API") onto `Phase`/
   `PhaseLinked`.

## 5. Proposal C: queue vectors, poll contexts and an ordered lifecycle

**Problem.** Patterns 7–9: interrupt plumbing per transport (300 lines),
the NAPI skeleton twice (300), probe/remove ceremony (300). Only
virtio-blk has per-queue vectors. Both net drivers are single-queue with
one NAPI.

**API** (`hw/pci/queue_irq.rs`, `hw/net/eth.rs`, `base/`):

```rust
/// Which queue an interrupt is for; `All` on a shared vector or INTx
pub enum QueueId { One(u16), All, Config }

pub trait QueueIrq: Send + Sync + 'static {
    /// Hard IRQ: ack/mask the queue's causes, schedule its poll; ours?
    fn irq(&self, q: QueueId) -> IrqReturn;
}

/// n queue vectors (+ `extra` for config/admin/link), queue i aimed at
/// group i of util::group_cpus; falls back to one shared vector, then
/// INTx with QueueId::All (Linux pci_alloc_irq_vectors_affinity with
/// PCI_IRQ_AFFINITY, min_vecs fallback)
pub struct QueueIrqs<H: QueueIrq> { /* MsixVectors + MsixHandler<..> | IrqRegistration<..> */ }
impl<H: QueueIrq> QueueIrqs<H> {
    pub fn request(pci: &PciDevice, n: u16, extra: u16, h: Arc<H>) -> KernelResult<Self>;
    pub fn nr_vectors(&self) -> u16;   // queues to create
    pub fn cpu(&self, q: u16) -> u32;  // blk-mq / XPS map
}

/// Ethernet engine: hadl-prep H3's EthDev<H: EthHw>, made per queue
pub trait EthChip: Send + Sync + 'static {
    type Queue: Send;                                  // rings + buffers of a TX/RX pair
    fn irq_ack(&self, q: QueueId) -> Option<u32>;      // causes; masks the queue
    fn irq_unmask(&self, q: u16);
    fn link_up(&self) -> bool;
    fn xmit(&self, q: &mut Self::Queue, skb: &SkBuff) -> KernelResult<()>;
    fn tx_clean(&self, q: &mut Self::Queue);
    fn rx(&self, q: &mut Self::Queue, budget: usize, out: &mut RxBatch) -> usize;
    fn start(&self) -> KernelResult<()>;  fn reset(&self);
}

pub struct EthDev<C: EthChip> {
    netdev: NetReg,                      // unregistered first on drop
    irqs: QueueIrqs<EthIrq<C>>,          // freed (synchronized) next
    q: KVec<QueueCtx<C::Queue>>,         // napi + spin::Mutex<Option<Queue>> + pending causes
    chip: Arc<C>,
    dma: DmaScope,                       // fenced last
}
```

- The engine owns the protocol: poll (budget, delivery after unlock,
  `napi_complete_done`, rearm under the queue lock with `netif_running`,
  the MISSED recheck), open/stop, `napi_off`, stats and remove.
- The fields drop in declaration order, so the struct encodes Linux's
  remove sequence: unregister, NAPI off, chip reset, free IRQs (which
  waits out handlers), fence DMA, free memory.
- A probe that fails part-way drops what it has built in reverse order,
  as devres does.
- A generic `base::Binding<T>` supplies `as_any`, `shutdown`'s stats line
  and `remove`, and replaces each driver's `Wrapper` and
  `try_box(MaybeUninit)` ceremony.

Fragment (e1000 probe on the engine):

```rust
fn e1000_probe(pdev: &Arc<Device>) -> KernelResult<Box<dyn Bound>> {
    let pci = pci_dev(pdev)?;
    let dma = DmaScope::new(pci)?;
    let chip = E1000::map(pci)?;                 // regs!, reset, MAC
    let q = HtQueue::new(&dma, 128, 64)?;        // Ring<RxDesc>, Ring<TxDesc>, DmaSlab bufs
    EthDev::probe(pdev, chip, [q], dma)          // vectors, NAPI, netdev, register
}
```

Block: blk-mq `MqOps` already is the per-queue boundary. `QueueIrqs`
replaces virtio-blk's `vectors` and virtio-pci's `IrqSlot`, and NVMe/AHCI
plug into both. xHCI: one interrupter means `n = 1` for now, while the
type allows secondary interrupters.

**LOC.**

| Driver | Before | After |
|---|---|---|
| e1000 ISR/poll/rearm/mask, ops/wrapper/remove, probe unwinding | 275 | 90 |
| virtio-net poll skeleton + probe | 254 | 80 |
| virtio-pci `IrqSlot`/vectors (the vector-to-queue config writes stay) | 140 | 40 |
| New igb-class multi-queue NIC (MSI-X per queue pair, NAPI per vector, compare `igb_alloc_q_vector`/`igb_request_msix`/`igb_set_interrupt_capability`/`igb_poll`, about 360 lines in Linux) | 350 | 60 |

The engine costs about 300 lines (`EthDev`), plus 150 (`QueueIrqs`) and
60 (`Binding`).

**Locking.**
- `QueueCtx.ring` keeps today's class: a `spin::Mutex`, thread-only (NAPI
  poll in `softnet/N`, xmit, open/stop), a leaf, with frames allocated
  `Gfp::ATOMIC` and delivered after unlock. The LOCKING.md 3.10 rows move
  from the e1000/virtio-net `rx`/`tx` rows to `EthDev` `QueueCtx.ring`,
  in the same commit as the code.
- ISRs still touch only registers, the `pending` atomic and
  `napi_schedule`.
- `QueueIrqs::request` and drop run in thread context only: `MATRIX`,
  then `IrqDesc.lock` per line, MSI-X masking under no lock, as today.
- The rule "IRQs free before the DMA fence" is enforced by field order
  and documented in 3.10.

**Per-CPU fit.**
- Vector i lands on its CPU group, and `napi_schedule` queues on the CPU
  that took the interrupt, so RX polling and TX cleaning stay on that CPU.
- TX picks a queue by current CPU (Linux XPS default), so each queue lock
  is in effect per CPU and uncontended.
- blk-mq maps CPUs to queues by the same `QueueIrqs::cpu`.

**Risks and open questions.**
- `NetDevice` has one `xmit` and no TX queue selection or per-queue
  stopped state (Linux `netdev_queue`, `ndo_select_queue`, `netif_tx_stop_queue`).
  Multi-queue TX needs that first.
- arm64 has no MSI until GICv3 ITS (ROADMAP D), so the fallback paths
  carry arm64.
- Generic engine vs dynamic dispatch: monomorphized `EthDev<C>` per chip,
  vs object-safe traits that HADL packages (data plus a C-ABI escape)
  could fill later. `EthChip`'s associated `Queue` is not object-safe.
- `EthDev` is HADL H3, which ROADMAP leaves unscheduled. `QueueIrqs` and
  `Binding` stand alone and fit D.

**Migration.**
1. `QueueIrqs` with D's MSI/MSI-X work: virtio-pci, then e1000 (MSI), then
   xHCI (n = 1).
2. `Binding` for the remaining drivers.
3. `EthDev` with e1000, then virtio-net (two gated commits).
4. RTL8168g and e1000e on it.
5. NVMe/AHCI on `QueueIrqs` + `Ring` + blk-mq.

## 6. Totals and order

| Driver | Today | With A+B+C |
|---|---|---|
| e1000 | 646 | ~270 |
| virtio-net | 418 | ~190 |
| xHCI (protocol-heavy; the gain is mostly safety) | 3238 | ~2690 |
| New igb-class NIC, multi-queue, page_pool RX, open-coded in today's style | ~1100 | ~450 + description |
| New NVMe minimum (admin + per-CPU I/O queues, PRP lists) | ~900 | ~400 |

The libraries cost about 1,350 lines once. They pay for themselves by the
second new DMA driver.

Order:
1. B's scope/array/slab with A's `dma_struct!` (M4; fixes the leaks and the
   `DmaBox` gap).
2. A's `regs!`.
3. xHCI conversion (M4).
4. C's `QueueIrqs` with D's MSI work.
5. C's `EthDev` (HADL H3, on the owner's go-ahead).

Every step is a gated, bisectable commit that converts its users and
updates LOCKING.md in the same commit.

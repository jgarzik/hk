# Rust idioms for hk: what pays off in LOC

Idioms (stable Rust, edition 2024) that cut boilerplate in the kernel crate. The LOC
left is in **lint-driven boilerplate**; `Default` pays in a few big constructors
(`Default` is not `const` on stable, so `const fn new()` stays for statics). These
items belong to doc/ROADMAP.md phase S1.

## Ranking (LOC saved per unit of risk)

| # | Item | Lines saved | Risk | Prio |
|---|------|-------------|------|------|
| 5 | Struct update `..Default::default()` in user/ | medium | low | med |
| 7 | One `util/bytes` LE/BE reader on `first_chunk` | small | low | low |
| 8 | `is_multiple_of` for `% a == 0` | none | none | low |
| 9 | xhci MMIO through `IoMem` | none | none | low |

---

## 5. Struct update syntax in user/: `..Default::default()`

Kernel literals left as they are, on purpose: `const fn` ctors and
`ZERO_CONTEXT` (`Default` isn't const on stable); types with a `Drop`
(`NetNamespace`, `PollContext`) or a field with no meaningful default
(`XhciController`'s `PciDevice`, `UsbDevice`'s `UsbSpeed`, the timer
inners' `HrClock`, `Task`, `CloneConfig`); and structs holding more than
one lock, since `derive(Default)` gives every lock in them the derive
line as its lockdep class.

- **user/:** the remaining zero-field literals use `..Default::default()`,
  or `..Zeroable::zeroed()` (user/syscall/types.rs) for types that cannot
  derive `Default`.


## 7. One LE/BE reader on `first_chunk` (1.77)

- **Evidence:** the same helper is reimplemented in several places:
  - block/part/mod.rs `le16`/`le32`/`le64` (panicking `try_into().unwrap()`)
  - arch/x86_64/multiboot2.rs `le32`/`le64`
  - arch/aarch64/pci_irq.rs `be32`
  - dt/mod.rs `read_be32`/`read_be64`
  - kmsg.rs `rd16`
  - hw/acpi/aml.rs `le`
  - hw/virtio/ring.rs test device `rd16`

  Plus `try_into().unwrap()` on slices in net/devioctl.rs, net/msg.rs,
  kmsg.rs, arch/x86_64/fpu.rs, arch/x86_64/signal.rs,
  hw/usb/pci_quirks.rs, net/netlink/rtnetlink.rs, net/packet/opts.rs,
  net/unix/scm.rs and block/part/mod.rs.
- **After:**
  ```rust
  pub fn le32(b: &[u8], o: usize) -> Option<u32> {
      b.get(o..)?.first_chunk().map(|a| u32::from_le_bytes(*a))
  }
  ```
  A small LOC cut, and the panicking `unwrap`s on disk or device data go away, as
  STYLE requires ("No panics on user input").
- **Risk:** low. Callers that index trusted kernel buffers may keep the infallible form.

## 8. `is_multiple_of` (1.87)

`% a == 0` sites and `& (PAGE_SIZE - 1) != 0` tests in mm/ remain.
Readability only, no LOC change. Hand-rolled
round-ups are gone, except `mm/heap.rs round_up` (run-time power-of-two
alignment on the allocation path: a mask, not a division), the wrapping
`mm/syscall.rs page_align` (Linux PAGE_ALIGN) and `mm/huge_page.rs` (mask
helpers next to their align-down twins).

## 9. xhci MMIO (rule 8)

hw/usb/xhci.rs registers are `IoMem` (`Regs`) except the IRQ handler's
USBSTS/IMAN acks through raw `(op_regs + off) as *const u32` (rule 8 / rule 2
wrapper).

## Smaller, optional

- `#[diagnostic::on_unimplemented]` (1.78) on `util/pod.rs` `FromBytes`/`IntoBytes`
  gives readable `pod!` errors ("field X is not plain data"). No LOC change.

## Comment LOC (not idioms; ROADMAP S2)

- `// =====` banner lines and `/// # Arguments` / `/// # Returns` sections
  on `sys_*` fns. These are the largest pure-comment LOC sinks; STYLE.md says
  comments should say why.

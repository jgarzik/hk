# TODO

Optional improvements; none of these is a bug.

- **ShmAttach::drop pairs with IPC_RMID only through the hardware**: the
  last detach does a SeqCst `fetch_sub` and then an Acquire load of
  `deleted`. IPC_RMID does store, fence(SeqCst), load. Under the Rust
  memory model a Dekker pairing needs a SeqCst fence (or a SeqCst load)
  on the detach side as well. x86 `lock xadd` and arm64 `stlxr`+`ldar`
  give the ordering anyway; one fence makes it formal. ipc/shm.rs:223,
  ipc/shm.rs:513.
- **Boot-once statics**: fpu `USE_XSAVE`/`XCR0`/
  `XSTATE_SIZE`/`MXCSR_MASK`, lapic `X2APIC`/`LAPIC_TICKS_PER_MS`,
  `SMAP_ON`, `PAN_ENABLED`, `INFO_PHYS`, `DTB_PHYS`, `DIRECT_END`, arm64
  `TIMER_FREQ`/`TICKS_PER_MS`, cache `CTR`. They are Relaxed atomics
  written before SMP, which is sound. Linux keeps them as
  `__ro_after_init` plain values. Convert them to `spin::Once` or
  initcall-set values, or at least give each a one-line
  `__ro_after_init` comment.

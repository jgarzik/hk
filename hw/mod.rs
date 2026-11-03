//! Hardware: code that touches a chip or device directly (registers,
//! port I/O, MMIO, device DMA). Generic layers above it (block, SCSI,
//! the driver model, the DRM-style UAPI) live outside hw/; per-CPU
//! architecture hardware lives in arch/.

pub mod acpi;
pub mod dma;
pub mod gfx;
pub mod mmio;
pub mod net;
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod serial;
pub mod usb;
pub mod virtio;

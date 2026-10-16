//! Virtio network device driver (virtio 1.2 section 5.1)
//!
//! Linux reference: drivers/net/virtio_net.c.
//!
//! ## Design
//!
//! - Features: VERSION_1 (12-byte `virtio_net_hdr_v1`), MAC, STATUS. No
//!   offloads (no CSUM/GSO: the stack sends and expects complete frames),
//!   no MRG_RXBUF, no control queue, one RX/TX queue pair, MTU 1500.
//! - Each queue has a pool of fixed 2 KiB bounce buffers in coherent DMA
//!   memory, one per descriptor; a buffer holds the header followed by
//!   the frame. Frames are copied into an skb on receive and out of it on
//!   transmit, so skb memory is never exposed to the device.
//! - RX: every buffer is posted at probe; the NAPI poll copies a completed
//!   buffer out and reposts it at once, then kicks once.
//! - TX: one descriptor per frame; completions are reclaimed by the next
//!   transmit and by every poll. TX interrupts stay suppressed. Ring full:
//!   the frame is dropped (`tx_dropped`, ENOBUFS), like a qdisc drop.
//! - Interrupts (transport INTx, see `virtio::pci`): a queue interrupt
//!   suppresses RX interrupts (avail NO_INTERRUPT, lock-free) and
//!   schedules NAPI; a config interrupt flags a link check and schedules
//!   NAPI. When the poll finishes under budget it completes NAPI and
//!   re-enables RX interrupts; buffers that arrived meanwhile (or a config
//!   change seen while it ran) make it reschedule itself (Linux
//!   virtqueue_napi_complete).
//! - Link: VIRTIO_NET_S_LINK_UP from the config status field (carrier
//!   on/off); without STATUS the link is always up.
//!
//! ## Locking (doc/LOCKING.md, Network)
//!
//! - ISR callbacks: lock-free (VringCb, atomics, `napi_schedule`).
//! - `rx`: `crate::sync::spin::Mutex`, thread context only (NAPI poll, open). Leaf.
//! - `tx`: `crate::sync::spin::Mutex`, thread context only (xmit, NAPI poll reclaim);
//!   taken under socket/ARP locks (end of the network lock order). Leaf.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::spin::Mutex;
use spin::Once;

use crate::bus::driver::{Device, DriverError};
use crate::dma::DmaCoherent;
use crate::net::dev::{
    NAPI_POLL_WEIGHT, Napi, NapiPoll, napi_complete_done, napi_disable, napi_enable, napi_schedule,
};
use crate::net::device::{LinkInfo, NetDevice, NetDeviceOps};
use crate::net::skb::{NET_SKB_PAD, SkBuff};
use crate::net::{self, KernelError};
use crate::printkln;
use crate::virtio::ring::{Sg, VringCb};
use crate::virtio::{self, VirtioDevice, VirtioDriver, VirtioIrq, Virtqueue};

/// Device-specific feature bits
mod feature {
    pub const MAC: u32 = 5;
    pub const STATUS: u32 = 16;
}

/// struct virtio_net_config offsets
mod cfg {
    pub const MAC: u32 = 0;
    pub const STATUS: u32 = 6;
}

/// Config status: link is up
const S_LINK_UP: u16 = 1;

/// struct virtio_net_hdr_v1 (VERSION_1: always 12 bytes)
const HDR_LEN: usize = 12;
/// Bounce buffer per descriptor (>= HDR_LEN + 1514, spec 5.1.6.3.1)
const BUF_SIZE: usize = 2048;
/// Largest frame accepted (VLAN-tagged 1500-byte payload, no FCS)
const MAX_FRAME: usize = 1518;
/// Largest frame sent
const MAX_TX: usize = BUF_SIZE - HDR_LEN;

const RXQ: u16 = 0;
const TXQ: u16 = 1;

/// Fixed-size bounce buffers in one coherent allocation
struct Pool {
    mem: DmaCoherent,
}

impl Pool {
    fn new(vdev: &VirtioDevice, n: u16) -> Result<Self, DriverError> {
        crate::dma::dma_alloc_coherent(vdev, n as usize * BUF_SIZE)
            .map(|mem| Self { mem })
            .ok_or(DriverError::MissingResource)
    }

    fn cpu(&self, i: usize) -> *mut u8 {
        unsafe { self.mem.cpu_addr.add(i * BUF_SIZE) }
    }

    fn dma(&self, i: usize) -> u64 {
        self.mem.dma_addr.0 + (i * BUF_SIZE) as u64
    }
}

struct RxQueue {
    vq: Virtqueue,
    pool: Pool,
}

struct TxQueue {
    vq: Virtqueue,
    pool: Pool,
    /// Buffers not in flight
    free: Vec<u16>,
}

impl RxQueue {
    /// Post buffer `i` to the device
    fn post(&mut self, i: usize) {
        let sg = Sg {
            addr: self.pool.dma(i),
            len: BUF_SIZE as u32,
        };
        // Cannot fail: one descriptor per buffer, as many as the ring
        let _ = self.vq.add(&[], &[sg], i);
    }
}

impl TxQueue {
    /// Reclaim buffers the device has sent
    fn reclaim(&mut self) {
        while let Some((i, _)) = self.vq.get() {
            self.free.push(i as u16);
        }
    }
}

/// virtio-net device state
struct VirtioNet {
    vdev: Arc<VirtioDevice>,
    mac: [u8; 6],
    rx: Mutex<RxQueue>,
    tx: Mutex<TxQueue>,
    /// IRQ-side handle on the RX queue's interrupt suppression
    rx_cb: VringCb,
    napi: Arc<Napi>,
    netdev: Once<Weak<NetDevice>>,
    /// A config interrupt not yet handled by the poll
    config_pending: AtomicBool,
}

impl VirtioNet {
    fn netdev(&self) -> Option<Arc<NetDevice>> {
        self.netdev.get()?.upgrade()
    }

    fn link_up(&self) -> bool {
        if !self.vdev.has_feature(feature::STATUS) {
            return true;
        }
        self.vdev.read_config(|d| d.cfg16(cfg::STATUS)) & S_LINK_UP != 0
    }

    fn update_carrier(&self, dev: &NetDevice) {
        let up = self.link_up();
        if up == dev.carrier_ok() {
            return;
        }
        if up {
            dev.netif_carrier_on();
        } else {
            dev.netif_carrier_off();
        }
        printkln!(
            "virtio-net: {} link {}",
            dev.name(),
            if up { "up" } else { "down" }
        );
    }

    fn transmit(&self, skb: &SkBuff) -> Result<(), KernelError> {
        let len = skb.len();
        if len == 0 || len > MAX_TX {
            return Err(KernelError::MessageTooLong);
        }
        let mut tx = self.tx.lock();
        tx.reclaim();
        let Some(i) = tx.free.pop() else {
            return Err(KernelError::NoBufferSpace);
        };
        let i = i as usize;
        unsafe {
            let b = tx.pool.cpu(i);
            // Zero header: no checksum or GSO offload
            core::ptr::write_bytes(b, 0, HDR_LEN);
            core::ptr::copy_nonoverlapping(skb.data_ptr(), b.add(HDR_LEN), len);
        }
        let sg = Sg {
            addr: tx.pool.dma(i),
            len: (HDR_LEN + len) as u32,
        };
        if tx.vq.add(&[sg], &[], i).is_err() {
            tx.free.push(i as u16);
            return Err(KernelError::NoBufferSpace);
        }
        tx.vq.kick();
        Ok(())
    }

    /// Copy a received buffer into an skb
    fn rx_skb(dev: &Arc<NetDevice>, buf: *const u8, len: usize) -> Option<Box<SkBuff>> {
        if !(HDR_LEN + 14..=HDR_LEN + MAX_FRAME).contains(&len) {
            dev.stats.inc_rx_errors();
            return None;
        }
        let len = len - HDR_LEN;
        // 2 extra bytes of headroom align the IP header (NET_IP_ALIGN)
        let Some(mut skb) = SkBuff::alloc(NET_SKB_PAD + 2, len) else {
            dev.stats.inc_rx_dropped();
            return None;
        };
        let src = unsafe { core::slice::from_raw_parts(buf.add(HDR_LEN), len) };
        let _ = skb.put_slice(src);
        skb.dev = Some(Arc::clone(dev));
        dev.stats.rx_packet(len);
        if src[0] & 1 != 0 {
            dev.stats.multicast.fetch_add(1, Ordering::Relaxed);
        }
        Some(skb)
    }

    /// Receive up to `budget` frames, reposting each buffer; frames are
    /// delivered by the caller after the lock is dropped
    #[allow(clippy::vec_box)] // skbs travel as Box<SkBuff> through the stack
    /// Returns the buffers consumed (bad frames count against the budget)
    fn receive(&self, dev: &Arc<NetDevice>, budget: usize, out: &mut Vec<Box<SkBuff>>) -> usize {
        let mut rx = self.rx.lock();
        let mut n = 0;
        while n < budget {
            let Some((i, len)) = rx.vq.get() else { break };
            if let Some(skb) = Self::rx_skb(dev, rx.pool.cpu(i), len as usize) {
                out.push(skb);
            }
            rx.post(i);
            n += 1;
        }
        if n > 0 {
            rx.vq.kick();
        }
        n
    }

    /// Re-enable RX interrupts after a completed poll while the device
    /// is running (checked under `rx`, which `stop` takes to suppress
    /// them, so a closing device stays suppressed); true if work arrived
    /// meanwhile and the poll must run again
    fn rearm(&self) -> bool {
        let rx = self.rx.lock();
        if !self.netdev().is_some_and(|d| d.netif_running()) {
            return false;
        }
        let pending = !rx.vq.enable_cb();
        drop(rx);
        pending || self.config_pending.load(Ordering::SeqCst)
    }
}

impl VirtioIrq for VirtioNet {
    fn vq_interrupt(&self) {
        self.rx_cb.disable();
        napi_schedule(&self.napi);
    }

    fn config_changed(&self) {
        self.config_pending.store(true, Ordering::Release);
        napi_schedule(&self.napi);
    }
}

impl NapiPoll for VirtioNet {
    fn poll(&self, napi: &Napi, budget: usize) -> usize {
        let dev = self.netdev();
        if let Some(d) = &dev
            && self.config_pending.swap(false, Ordering::AcqRel)
        {
            self.update_carrier(d);
        }

        self.tx.lock().reclaim();

        let mut frames = Vec::new();
        let work = match &dev {
            Some(d) => self.receive(d, budget, &mut frames),
            None => 0,
        };
        for skb in frames {
            net::dev::netif_receive_skb(skb);
        }

        if work < budget {
            napi_complete_done(napi, work);
            // A closed device keeps RX interrupts suppressed
            if self.rearm() {
                self.rx_cb.disable();
                napi_schedule(&self.napi);
            }
        }
        work
    }
}

// ============================================================================
// Net device glue
// ============================================================================

struct VirtioNetOps {
    device: Arc<VirtioNet>,
}

impl NetDeviceOps for VirtioNetOps {
    fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        self.device.transmit(&skb)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.device.mac
    }

    fn mtu(&self) -> u32 {
        1500
    }

    fn max_mtu(&self) -> u32 {
        1500 // fixed 2 KiB buffers, no MRG_RXBUF
    }

    fn open(&self, dev: &NetDevice) -> Result<(), KernelError> {
        let d = &self.device;
        d.update_carrier(dev);
        napi_enable(&d.napi);
        if d.rearm() {
            d.rx_cb.disable();
            napi_schedule(&d.napi);
        }
        Ok(())
    }

    /// NAPI off (waits for a running poll), then suppress RX interrupts
    fn stop(&self) -> Result<(), KernelError> {
        napi_disable(&self.device.napi);
        let _rx = self.device.rx.lock();
        self.device.rx_cb.disable();
        Ok(())
    }
}

struct VirtioNetWrapper {
    netdev: Arc<NetDevice>,
    device: Arc<VirtioNet>,
}

impl Device for VirtioNetWrapper {
    fn name(&self) -> &str {
        "virtio-net"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn shutdown(&self) {
        printkln!(
            "virtio-net: {} irqs={} napi_polls={}",
            self.netdev.name(),
            self.device.vdev.irqs(),
            self.device.napi.polls(),
        );
        self.device.rx_cb.disable();
    }
}

/// The virtio-net driver (registered with `virtio::register_driver`)
pub struct VirtioNetDriver;

pub static VIRTIO_NET: VirtioNetDriver = VirtioNetDriver;

fn read_mac(vdev: &VirtioDevice) -> [u8; 6] {
    if vdev.has_feature(feature::MAC) {
        return vdev.read_config(|d| core::array::from_fn(|i| d.cfg8(cfg::MAC + i as u32)));
    }
    // No MAC from the device: random, locally administered (Linux
    // eth_hw_addr_random)
    let mut mac = [0u8; 6];
    let _ = crate::random::get_random_bytes(&mut mac, 0);
    mac[0] = (mac[0] & 0xFE) | 0x02;
    mac
}

fn setup_queues(vdev: &VirtioDevice) -> Result<(RxQueue, TxQueue), DriverError> {
    let rvq = vdev.setup_vq(RXQ)?;
    let tvq = vdev.setup_vq(TXQ)?;
    let mut rx = RxQueue {
        pool: Pool::new(vdev, rvq.num())?,
        vq: rvq,
    };
    let tx = TxQueue {
        pool: Pool::new(vdev, tvq.num())?,
        free: (0..tvq.num()).rev().collect(),
        vq: tvq,
    };
    for i in 0..rx.vq.num() as usize {
        rx.post(i);
    }
    // Interrupts are suppressed until the interface is opened (RX) or
    // for good (TX: reclaimed by xmit and poll)
    rx.vq.disable_cb();
    tx.vq.disable_cb();
    Ok((rx, tx))
}

impl VirtioDriver for VirtioNetDriver {
    fn name(&self) -> &'static str {
        "virtio-net"
    }

    fn device_id(&self) -> u32 {
        virtio::id::NET
    }

    fn features(&self) -> u64 {
        (1 << feature::MAC) | (1 << feature::STATUS)
    }

    fn probe(&self, vdev: Arc<VirtioDevice>) -> Result<Box<dyn Device>, DriverError> {
        let mac = read_mac(&vdev);
        let (rx, tx) = setup_queues(&vdev)?;
        let rx_cb = rx.vq.cb();
        let device = Arc::new(VirtioNet {
            vdev: Arc::clone(&vdev),
            mac,
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
            rx_cb,
            napi: Napi::new(NAPI_POLL_WEIGHT),
            netdev: Once::new(),
            config_pending: AtomicBool::new(false),
        });
        let poller: Weak<dyn NapiPoll> = Arc::downgrade(&device) as Weak<dyn NapiPoll>;
        net::dev::netif_napi_add(&device.napi, poller);

        let irq = vdev
            .request_irq(Arc::clone(&device) as Arc<dyn VirtioIrq>)
            .map_err(|e| {
                printkln!("virtio-net: no IRQ ({})", e);
                DriverError::MissingResource
            })?;
        vdev.ready();
        // Buffers were posted before DRIVER_OK; notify only now (spec 3.1.1)
        device.rx.lock().vq.kick();

        let ops: &'static dyn NetDeviceOps = Box::leak(Box::new(VirtioNetOps {
            device: Arc::clone(&device),
        }));
        // RTNL from naming to registration (Linux register_netdev)
        let (rtnl, netdev) = net::alloc_netdev("eth%d", mac, LinkInfo::ETHER, ops);
        device.netdev.call_once(|| Arc::downgrade(&netdev));
        // Carrier now; later changes arrive as config interrupts
        if device.link_up() {
            netdev.netif_carrier_on();
        } else {
            netdev.netif_carrier_off();
        }
        printkln!(
            "virtio-net: {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} IRQ {} link {}",
            netdev.name(),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            irq,
            if device.link_up() { "up" } else { "down" }
        );
        net::register_netdev(rtnl, Arc::clone(&netdev));
        Ok(Box::new(VirtioNetWrapper { netdev, device }))
    }
}

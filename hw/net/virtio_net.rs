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
//! - Probe (Linux virtnet_probe): the device state is allocated before
//!   the queues (alloc_etherdev before init_vqs), so no allocation after
//!   them can fail; a failure after the queues are set up resets the
//!   device and frees their rings (`del_vqs`), then the bounce buffers
//!   (`DmaBox`, freed on drop).
//! - Remove (Linux virtnet_remove): `unregister_netdev` (closes it: NAPI
//!   off), NAPI off if it never was, the device reset, the IRQ freed,
//!   then the rings and bounce buffers freed (`del_vqs`). A reset that
//!   does not complete leaks them instead (Linux vp_reset waits for it
//!   without a limit).
//!
//! ## Locking (doc/LOCKING.md, Network)
//!
//! - ISR callbacks: lock-free (VringCb, atomics, `napi_schedule`).
//! - `rx`: `crate::sync::spin::Mutex`, thread context only (NAPI poll,
//!   open, stop, remove). Leaf. Empty once removed.
//! - `tx`: `crate::sync::spin::Mutex`, thread context only (xmit, NAPI poll reclaim);
//!   taken under socket/ARP locks (end of the network lock order). Leaf.
//!   Empty once removed.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::mm::page_alloc::Gfp;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::spin::Mutex;
use spin::Once;

use crate::hw::dma::DmaBox;
use crate::hw::virtio::ring::{Sg, VringCb};
use crate::hw::virtio::{self, VirtioDevice, VirtioDriver, VirtioIrq, Virtqueue};
use crate::net;
use crate::net::dev::{
    NAPI_POLL_WEIGHT, Napi, NapiPoll, napi_complete_done, napi_disable, napi_enable, napi_schedule,
    netif_napi_del,
};
use crate::net::device::{LinkInfo, NetDevice, NetDeviceOps};
use crate::net::skb::{NET_SKB_PAD, SkBuff, SkbHead};
use crate::printkln;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_write, try_arc_uninit, try_box};
use crate::util::kmem::try_vec_with;

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

/// Fixed-size bounce buffers in one coherent allocation (freed on
/// drop: only once the device is reset, or never given them)
struct Pool {
    mem: DmaBox,
}

impl Pool {
    fn new(vdev: &VirtioDevice, n: u16) -> Result<Self, KernelError> {
        DmaBox::alloc(vdev, n as usize * BUF_SIZE)
            .map(|mem| Self { mem })
            .ok_or(KernelError::OutOfMemory)
    }

    fn cpu(&self, i: usize) -> *mut u8 {
        unsafe { self.mem.cpu_addr().add(i * BUF_SIZE) }
    }

    fn dma(&self, i: usize) -> u64 {
        self.mem.dma_addr().0 + (i * BUF_SIZE) as u64
    }
}

struct RxQueue {
    vq: Virtqueue,
    pool: Pool,
    /// NAPI is disabled (by `stop`; enabled from probe and by `open`)
    napi_off: bool,
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
    /// None once removed
    rx: Mutex<Option<RxQueue>>,
    tx: Mutex<Option<TxQueue>>,
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
        let tx = tx.as_mut().ok_or(KernelError::NoDevice)?;
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
    ///
    /// # Safety
    /// `buf` is a receive buffer of at least HDR_LEN + MAX_FRAME bytes
    /// that the device has returned and that is not reposted meanwhile.
    unsafe fn rx_skb(dev: &Arc<NetDevice>, buf: *const u8, len: usize) -> Option<Box<SkBuff>> {
        if !(HDR_LEN + 14..=HDR_LEN + MAX_FRAME).contains(&len) {
            dev.stats.inc_rx_errors();
            return None;
        }
        let len = len - HDR_LEN;
        // 2 extra bytes of headroom align the IP header (NET_IP_ALIGN)
        let Some(mut skb) = SkBuff::alloc(NET_SKB_PAD + 2, len, Gfp::ATOMIC) else {
            dev.stats.inc_rx_dropped();
            return None;
        };
        // SAFETY: inside the returned buffer (len checked against
        // MAX_FRAME above; caller)
        let src = unsafe { core::slice::from_raw_parts(buf.add(HDR_LEN), len) };
        let _ = skb.put_slice(src);
        skb.dev = Some(Arc::clone(dev));
        dev.stats.rx_packet(len);
        if src[0] & 1 != 0 {
            dev.stats.inc_multicast();
        }
        Some(skb)
    }

    /// Receive up to `budget` frames onto `out`, linked through their
    /// own `list` (Linux napi_alloc_skb, GFP_ATOMIC under the queue
    /// lock), reposting each buffer; the caller delivers them after the
    /// lock is dropped. Returns the buffers consumed (bad frames count
    /// against the budget).
    fn receive(
        &self,
        dev: &Arc<NetDevice>,
        budget: usize,
        out: &mut SkbHead<Box<SkBuff>>,
    ) -> usize {
        let mut rx = self.rx.lock();
        let Some(rx) = rx.as_mut() else { return 0 };
        let mut n = 0;
        while n < budget {
            let Some((i, len)) = rx.vq.get() else { break };
            // SAFETY: buffer `i` came back from the device (vq.get) and
            // is reposted only below
            if let Some(skb) = unsafe { Self::rx_skb(dev, rx.pool.cpu(i), len as usize) } {
                out.push_back(skb);
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
        let Some(rx) = rx.as_ref() else { return false };
        if !self.netdev().is_some_and(|d| d.netif_running()) {
            return false;
        }
        let pending = !rx.vq.enable_cb();
        pending || self.config_pending.load(Ordering::SeqCst)
    }
}

impl VirtioIrq for VirtioNet {
    fn vq_interrupt(&self, _vq: Option<u16>) {
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

        if let Some(tx) = self.tx.lock().as_mut() {
            tx.reclaim();
        }

        // Delivered with the queue lock dropped (Linux napi_gro_receive
        // runs outside the driver's locks)
        let mut frames = SkbHead::new();
        let work = match &dev {
            Some(d) => self.receive(d, budget, &mut frames),
            None => 0,
        };
        while let Some(skb) = frames.pop_front() {
            net::dev::netif_receive_skb(skb);
        }

        // Linux virtqueue_napi_complete: re-check only if done (a MISSED
        // completion polls again)
        if work < budget && napi_complete_done(napi, work) {
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
        if let Some(rx) = d.rx.lock().as_mut() {
            rx.napi_off = false;
        }
        if d.rearm() {
            d.rx_cb.disable();
            napi_schedule(&d.napi);
        }
        Ok(())
    }

    /// NAPI off (waits for a running poll), then suppress RX interrupts
    fn stop(&self) -> Result<(), KernelError> {
        napi_disable(&self.device.napi);
        let mut rx = self.device.rx.lock();
        if let Some(rx) = rx.as_mut() {
            rx.napi_off = true;
        }
        self.device.rx_cb.disable();
        Ok(())
    }
}

struct VirtioNetWrapper {
    netdev: Arc<NetDevice>,
    device: Arc<VirtioNet>,
}

impl crate::base::Bound for VirtioNetWrapper {
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

    /// Linux virtnet_remove
    fn remove(&self) {
        let d = &self.device;
        net::unregister_netdev(&self.netdev);
        // Closed: NAPI is off; never opened (or closed and polled for a
        // config change): stop it now, waiting for a running poll
        let off = d.rx.lock().as_ref().is_none_or(|q| q.napi_off);
        if !off {
            napi_disable(&d.napi);
        }
        // Quiet before its IRQ goes (Linux remove_vq_common: reset,
        // then del_vqs frees the IRQ)
        let _ = d.vdev.reset();
        d.vdev.free_irq();
        virtnet_del_vqs(d);
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

/// The RX and TX queues with their bounce buffers, every RX buffer
/// posted (Linux init_vqs + the probe's buffer setup). On a failure
/// what was set up goes again: the rings after a reset (`del_vqs`,
/// Linux vp_find_vqs' error path), the buffers, never given to the
/// device, with their owners.
fn setup_queues(vdev: &VirtioDevice) -> Result<(RxQueue, TxQueue), KernelError> {
    let rvq = vdev.setup_vq(RXQ)?;
    let tvq = match vdev.setup_vq(TXQ) {
        Ok(q) => q,
        Err(e) => {
            let _ = vdev.del_vqs([rvq]);
            return Err(e);
        }
    };
    let bufs = (|| {
        let rp = Pool::new(vdev, rvq.num())?;
        let tp = Pool::new(vdev, tvq.num())?;
        let mut k = tvq.num();
        let free = try_vec_with(usize::from(k), || {
            k -= 1;
            k
        })?;
        Ok((rp, tp, free))
    })();
    let (rpool, tpool, free) = match bufs {
        Ok(b) => b,
        Err(e) => {
            let _ = vdev.del_vqs([rvq, tvq]);
            return Err(e);
        }
    };
    let mut rx = RxQueue {
        pool: rpool,
        vq: rvq,
        napi_off: false,
    };
    let tx = TxQueue {
        pool: tpool,
        free,
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

/// Linux virtnet_del_vqs: the device reset and the queues' rings freed
/// (del_vqs), the NAPI context deleted (virtnet_free_queues), then the
/// bounce buffers freed; a reset that does not complete leaks rings and
/// buffers alike (the device may still use them)
fn virtnet_del_vqs(d: &VirtioNet) {
    netif_napi_del(&d.napi);
    let rx = d.rx.lock().take();
    let tx = d.tx.lock().take();
    let (Some(rx), Some(tx)) = (rx, tx) else {
        return;
    };
    let pools = (rx.pool, tx.pool);
    if d.vdev.del_vqs([rx.vq, tx.vq]).is_err() {
        printkln!("virtio-net: {}: reset failed", d.vdev.bus_id());
        core::mem::forget(pools);
    }
}

impl VirtioDriver for VirtioNetDriver {
    fn features(&self) -> u64 {
        (1 << feature::MAC) | (1 << feature::STATUS)
    }

    /// Linux virtnet_probe
    fn probe(
        &self,
        dev: &Arc<crate::base::Device>,
        vdev: Arc<VirtioDevice>,
    ) -> Result<Box<dyn crate::base::Bound>, KernelError> {
        // The binding's and the device state's memory first: nothing to
        // undo should they fail (Linux alloc_etherdev before init_vqs)
        let slot = try_box(MaybeUninit::<VirtioNetWrapper>::uninit())?;
        let dmem = try_arc_uninit::<VirtioNet>()?;
        let omem = try_arc_uninit::<VirtioNetOps>()?;
        let mac = read_mac(&vdev);
        let (rx, tx) = setup_queues(&vdev)?;
        let rx_cb = rx.vq.cb();
        let device = arc_write(
            dmem,
            VirtioNet {
                vdev: Arc::clone(&vdev),
                mac,
                rx: Mutex::new(Some(rx)),
                tx: Mutex::new(Some(tx)),
                rx_cb,
                napi: Napi::new(NAPI_POLL_WEIGHT),
                netdev: Once::new(),
                config_pending: AtomicBool::new(false),
            },
        );
        let ops: Arc<dyn NetDeviceOps> = arc_write(
            omem,
            VirtioNetOps {
                device: Arc::clone(&device),
            },
        );
        let poller: Weak<dyn NapiPoll> = Arc::downgrade(&device) as Weak<dyn NapiPoll>;
        net::dev::netif_napi_add(&device.napi, poller);

        let irq = match vdev.request_irq(Arc::clone(&device) as Arc<dyn VirtioIrq>) {
            Ok(irq) => irq,
            Err(e) => {
                printkln!("virtio-net: no IRQ ({:?})", e);
                // Linux virtnet_probe's free: reset, virtnet_del_vqs
                virtnet_del_vqs(&device);
                return Err(KernelError::NoDevice);
            }
        };
        vdev.ready();
        // Buffers were posted before DRIVER_OK; notify only now (spec 3.1.1)
        if let Some(rx) = device.rx.lock().as_mut() {
            rx.vq.kick();
        }

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
        netdev.parent.call_once(|| dev.clone());
        net::register_netdev(rtnl, Arc::clone(&netdev));
        Ok(Box::write(slot, VirtioNetWrapper { netdev, device }))
    }
}

/// The virtio_net driver on the virtio bus
pub static VIRTIO_NET_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "virtio_net",
    &virtio::VIRTIO_BUS,
    None,
    &virtio::VirtioIds {
        ids: &[(virtio::id::NET, virtio::VIRTIO_DEV_ANY_ID)],
        drv: &VIRTIO_NET,
    },
    virtio::virtio_dev_probe,
);

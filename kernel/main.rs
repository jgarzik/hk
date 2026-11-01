//! hk kernel entry point
//!
//! This is the main kernel binary that ties together all components.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
// Host unit tests (`make test`) build only a subset; skip dead-code noise
#![cfg_attr(test, allow(dead_code, unused))]

extern crate alloc;

// Core modules (formerly in core/ subdir)
pub mod acct;
pub mod acpi;
pub mod bus;
pub mod chardev;
pub mod completion;
pub mod console;
pub mod cpu;
pub mod cpumask;
pub mod delay;
pub mod dma;
pub mod elf;
pub mod entry;
pub mod epoll;
pub mod eventfd;
pub mod fanotify;
pub mod futex;
pub mod hrtimer;
pub mod inotify;
pub mod io_uring;
pub mod irq;
pub mod kcmp;
pub mod kmem;
pub mod list;
pub mod pidfd;
pub mod pipe;
pub mod poll;
pub mod posix_timer;
pub mod printk;
pub mod selftest;
pub mod signalfd;
pub mod smp;
pub mod storage;
pub mod sync;
pub mod sysctl;
mod time;
pub mod timer;
pub mod timerfd;
pub mod uaccess;
pub mod waitqueue;
pub mod watchdog;
pub mod workqueue;

// Device subsystems
pub mod dt;
pub mod gfx;
pub mod net;
pub mod tty;
pub mod usb;
pub mod virtio;

// printkln macro is re-exported at crate root via #[macro_export]

// Multiboot2 header is in boot.S

mod arch;
mod binfmt_script;
pub mod bpf;
pub mod cgroup;
mod cmdline;
pub mod error;
mod frame_alloc;
pub mod fs;
mod heap;
pub mod ipc;
pub mod keys;
mod kmsg;
pub mod membarrier;
pub mod mm;
#[cfg(target_arch = "x86_64")]
mod multiboot2;
pub mod ns;
pub mod numa;
mod power;
mod random;
mod rlimit;
pub mod seccomp;
pub mod signal;
pub mod task;
mod time_syscall;

#[cfg(not(test))]
use ::core::panic::PanicInfo;

// Architecture type alias for generic kernel code
#[cfg(target_arch = "x86_64")]
type CurrentArch = crate::arch::x86_64::X86_64Arch;

#[cfg(target_arch = "aarch64")]
type CurrentArch = crate::arch::aarch64::Aarch64Arch;

// Import architecture traits for trait method calls
use crate::arch::ArchBusOps;
use crate::arch::SchedArch;
use crate::arch::{
    AcpiOps, CpuOps, EarlyArchInit, ExceptionOps, HaltOps, InitramfsOps, IoremapOps, LocalTimerOps,
    MemoryLayoutOps, PowerOps, SmpOps, TimekeeperOps, VfsInitOps,
};

// Page table type alias (used by ELF loading)
type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

use crate::dma::{DirectDmaOps, dma_init};
use crate::mm::page_cache::PageCache;

#[allow(unused_imports)]
use fs::inode::AsAny; // Trait needed for .as_any() on dyn InodeData

use crate::sync::spin::Mutex;

/// Kernel heap: boot arena, then slab (host unit tests use the std
/// allocator)
#[cfg_attr(not(test), global_allocator)]
static ALLOCATOR: heap::KernelAlloc = heap::KernelAlloc::new();

/// Global page cache (1024 evictable pages = 4MB max)
static PAGE_CACHE: Mutex<PageCache> = Mutex::new(PageCache::new(1024));

/// Global frame allocator
static FRAME_ALLOCATOR: frame_alloc::FrameAllocator = frame_alloc::FrameAllocator::new();

/// Global DMA operations (direct mapping backend)
static DIRECT_DMA_OPS: DirectDmaOps = DirectDmaOps::new(&FRAME_ALLOCATOR);

/// Invalidate all page cache entries for a block device (hotplug removal)
///
/// Called when a block device is removed to free cached pages.
/// Returns the number of pages that were invalidated.
pub fn invalidate_blkdev_pages(major: u16, minor: u16) -> usize {
    let mut alloc_ref = frame_alloc::FrameAllocRef(&FRAME_ALLOCATOR);
    PAGE_CACHE
        .lock()
        .invalidate_blkdev(major, minor, &mut alloc_ref)
}

/// Multiboot2 info pointer (set by _start, used by kmain) - x86_64 only
#[cfg(target_arch = "x86_64")]
pub static mut MULTIBOOT2_INFO: u64 = 0;

/// Device Tree Blob pointer (set by _start_rust, used by kmain) - aarch64 only
#[cfg(target_arch = "aarch64")]
pub static mut DTB_PTR: u64 = 0;

/// Embedded initramfs for aarch64 (fallback when DTB doesn't provide initramfs)
/// This embeds the initramfs directly into the kernel binary.
#[cfg(target_arch = "aarch64")]
pub static EMBEDDED_INITRAMFS: &[u8] = include_bytes!("../user/initramfs-aarch64.cpio");

/// x86_64 Kernel entry point called by bootloader
///
/// multiboot_info: Pointer to multiboot2 info structure (passed in RDI)
#[cfg(all(target_arch = "x86_64", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn _start(multiboot_info: u64) -> ! {
    // Kernel page table first: the boot tables' identity map goes away
    unsafe {
        arch::x86_64::kmap::init(multiboot_info);
        MULTIBOOT2_INFO = multiboot_info;
    }

    // Messages before console attach are buffered
    printkln!("hk kernel starting...");

    // Initialize VGA text console for early output
    arch::x86_64::vgacon::init_vgacon();

    // Initialize serial console (through TTY layer)
    tty::serial::init_serial_console();

    // Flush buffered messages to console
    crate::printk::flush();

    // Print and parse kernel command line (if any)
    if let Some(cmdline) = unsafe { multiboot2::get_cmdline(multiboot_info) }
        && !cmdline.is_empty()
    {
        printkln!("Cmdline: {}", cmdline);
        cmdline::parse_cmdline(cmdline);
    }

    // Initialize architecture-specific code (GDT, IDT, PIC, PIT)
    CurrentArch::early_init();

    // Continue to main kernel
    kmain()
}

/// AArch64 Kernel entry point called from boot.S
///
/// dtb_ptr: Pointer to Device Tree Blob (passed in x0)
#[cfg(all(target_arch = "aarch64", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn _start_rust(dtb_ptr: u64) -> ! {
    // Initialize serial FIRST before anything else
    crate::arch::aarch64::serial::init();

    // Save DTB pointer for later use
    unsafe {
        DTB_PTR = dtb_ptr;
    }

    // Direct serial output for early boot debugging (bypasses console subsystem)
    crate::arch::aarch64::serial::write_str("hk kernel starting... (aarch64)\r\n");

    // Find DTB in memory (QEMU virt ELF boot places DTB at RAM start);
    // the boot tables linear-map the first RAM gigabyte
    {
        const DTB_MAGIC_BE: u32 = 0xd00dfeed;
        let magic = |pa: u64| unsafe {
            ::core::ptr::read_volatile(crate::arch::phys_to_virt(pa) as *const u32)
        };
        let found = [0x4000_0000, 0x4008_0000, 0x4400_0000, 0x4800_0000]
            .into_iter()
            .chain((0x4200_0000u64..0x6000_0000).step_by(0x1000))
            .find(|&pa| magic(pa).swap_bytes() == DTB_MAGIC_BE);
        if let Some(pa) = found {
            unsafe { DTB_PTR = pa };
        }
    }

    // Initialize architecture (CPU features, RTC, etc.)
    CurrentArch::early_init();

    // Final kernel page tables (linear map of all RAM, which goes to
    // memblock)
    unsafe { crate::arch::aarch64::kmap::init(DTB_PTR) };

    // Extract and parse kernel command line from DTB /chosen/bootargs
    if let Some(cmdline) = crate::arch::aarch64::dtb::extract_bootargs(unsafe { DTB_PTR })
        && !cmdline.is_empty()
    {
        printkln!("Cmdline: {}", cmdline);
        cmdline::parse_cmdline(cmdline);
    }

    // Continue to unified main kernel
    kmain()
}

use crate::mm::STACK_TOP as USER_STACK_TOP;

/// Initialize NUMA topology from firmware
///
/// On x86-64, parses ACPI SRAT/SLIT tables.
/// On aarch64, extracts numa-node-id properties from device tree.
///
/// Falls back to single-node topology if no NUMA info is available.
fn init_numa_topology() {
    let total_pages = mm::memblock::MEMBLOCK.lock().memory.total() / 4096;
    let nr_cpus = 1; // Will be updated when SMP is initialized

    #[cfg(target_arch = "x86_64")]
    {
        match arch::x86_64::acpi::init_numa_topology() {
            Ok(true) => {
                numa::print_topology();
                return;
            }
            Ok(false) => {
                // No SRAT table, use single-node fallback
            }
            Err(e) => {
                printkln!("NUMA: ACPI parse error: {}", e);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let dtb_ptr = unsafe { DTB_PTR };
        match arch::aarch64::dtb::init_numa_topology(dtb_ptr) {
            Ok(true) => {
                numa::print_topology();
                return;
            }
            Ok(false) => {
                // No numa-node-id properties, use single-node fallback
            }
            Err(e) => {
                printkln!("NUMA: DTB parse error: {}", e);
            }
        }
    }

    // Fallback to single-node topology
    numa::init_single_node_fallback(total_pages, nr_cpus);
}

/// Discover boot framebuffer from firmware
///
/// On x86-64, parses the multiboot2 framebuffer tag.
/// On aarch64, parses the device tree simple-framebuffer node.
///
/// Stores the result in BOOT_FRAMEBUFFER and reserves the memory.
fn discover_boot_framebuffer() {
    use gfx::{BOOT_FRAMEBUFFER, FramebufferInfo};

    let fb_info: Option<FramebufferInfo>;

    #[cfg(target_arch = "x86_64")]
    {
        // Parse multiboot2 framebuffer tag
        fb_info = unsafe { multiboot2::get_framebuffer(MULTIBOOT2_INFO) };
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Parse device tree simple-framebuffer node
        fb_info = unsafe { arch::aarch64::dtb::extract_simple_framebuffer(DTB_PTR) };
    }

    if let Some(info) = fb_info {
        printkln!(
            "FB: {}x{} @ {:#x} ({} bytes, pitch={})",
            info.width,
            info.height,
            info.phys_addr,
            info.size,
            info.pitch
        );

        // Keep it from the frame allocator (when it is in RAM)
        mm::memblock::reserve(info.phys_addr, info.size);

        // Store for later use by graphics subsystem
        BOOT_FRAMEBUFFER.call_once(|| info);
    }
}

/// Main kernel function (unified for all architectures)
fn kmain() -> ! {
    // ========================================================================
    // Phase 1: Memory Subsystem
    // ========================================================================

    // Firmware memory map and boot reservations (multiboot2 on x86,
    // DTB on arm), then every free range goes to the frame allocator
    CurrentArch::memblock_init();
    discover_boot_framebuffer();
    let (lo, hi) = mm::memblock::MEMBLOCK.lock().span();
    mm::page::vmemmap_init();
    FRAME_ALLOCATOR.init(lo, hi - lo);
    mm::memblock::MEMBLOCK
        .lock()
        .for_each_free(|start, end| FRAME_ALLOCATOR.free_range(start, end));
    FRAME_ALLOCATOR.init_done();
    printkln!("MEM: boot arena {} kB in use", ALLOCATOR.arena_used() >> 10);
    ALLOCATOR.slab_ready();
    printkln!("MEM: {} MB", FRAME_ALLOCATOR.stats().total_bytes >> 20);

    // Initialize DMA subsystem (uses frame allocator)
    dma_init(&DIRECT_DMA_OPS);

    // Run page cache self-tests (verifies locking correctness)
    crate::mm::page_cache::run_self_tests();

    // Initialize ioremap subsystem (MMIO virtual address management)
    CurrentArch::ioremap_init();

    // ========================================================================
    // Phase 1b: NUMA Topology Discovery
    // ========================================================================
    // Initialize NUMA topology from firmware (ACPI SRAT on x86, DTB numa-node-id on arm)
    // This must happen after ioremap_init but before SMP init
    init_numa_topology();

    // ========================================================================
    // Phase 2: Exception/Interrupt Subsystem
    // ========================================================================

    // Initialize exception vectors and interrupt controller
    // (no-op on x86 where this is done in early_init, GIC init on arm)
    CurrentArch::init_exceptions();

    // Create a reference wrapper for use with APIs requiring &mut FrameAlloc
    let mut frame_alloc = frame_alloc::FrameAllocRef(&FRAME_ALLOCATOR);

    // ========================================================================
    // Phase 3: Platform Discovery and SMP
    // ========================================================================

    // Initialize SMP (bring up additional CPUs)
    if let Some(mut acpi_info) = CurrentArch::parse_acpi() {
        // Initialize power management from ACPI/device tree
        if let Some(power_info) = &acpi_info.power_info {
            CurrentArch::power_init(power_info);
        }

        // Map local interrupt controller MMIO region
        match CurrentArch::ioremap(acpi_info.interrupt_controller_base, 4096) {
            Err(e) => {
                printkln!("SMP: Failed to ioremap interrupt controller: {:?}", e);
            }
            Ok(ic_virt) => {
                // Initialize local interrupt controller
                unsafe {
                    CurrentArch::init_local_interrupt_controller(ic_virt as u64);
                }

                // Read BSP CPU ID and initialize SMP
                let bsp_id = CurrentArch::current_hw_cpu_id();
                CurrentArch::set_bsp_cpu_id(&mut acpi_info, bsp_id);

                let online = CurrentArch::smp_init(&acpi_info, &mut frame_alloc);
                smp::init(online as u32);

                // Calibrate and start local timer (10ms interval)
                let ticks_per_ms = CurrentArch::calibrate_and_start_timer(
                    CurrentArch::TIMER_VECTOR,
                    10, // 10ms = 100Hz
                );
                printkln!("TIMER: {} ticks/ms, {} CPUs", ticks_per_ms, online);

                // Initialize clock source for timekeeping
                if let Some(clock) = CurrentArch::init_clock_source() {
                    let freq = CurrentArch::clock_frequency(&clock);
                    let rtc_time = CurrentArch::read_rtc();
                    crate::time::TIMEKEEPER.init(rtc_time, freq, CurrentArch::read_cycles);
                    printkln!("CLOCK: {} Hz, RTC={}", freq, rtc_time);

                    // Initialize CRNG (uses cycle counter for entropy)
                    crate::random::init();
                }

                // Enable APs to start their timers and participate in scheduling
                CurrentArch::enable_ap_scheduling();

                // This CPU answers IPIs once it takes interrupts (its
                // first task enables them)
                smp::set_active(crate::cpu::this_id());
            }
        }
    } else {
        printkln!("SMP: Platform discovery failed (ACPI/device tree)");
    }

    // ACPI mode (Linux acpi_bus_init -> acpi_enable_subsystem), timed by
    // the timekeeper started above
    CurrentArch::power_enable();

    // Initialize network subsystem (sets up loopback, static IP config)
    crate::net::init();

    // ========================================================================
    // Phase 4: The scheduler runs (Linux sched_init, rest_init): the boot
    // context becomes pid 1 in kernel mode with interrupts on, so driver
    // probe, VFS setup and the initramfs below may sleep like any task.
    // Its program is loaded into the address space made here once the
    // initramfs is unpacked (Linux kernel_init, then run_init_process).
    // ========================================================================
    let mut user_pt = match ArchPageTable::new_user(&mut frame_alloc) {
        Some(pt) => pt,
        None => {
            printkln!("ERR: page table alloc");
            CurrentArch::halt_loop();
        }
    };
    user_pt.copy_kernel_mappings();
    // Its stack comes with the program exec loads into it (run_init)
    let user_stack_top = USER_STACK_TOP;
    // Kernel stack for PID 1 (init process)
    let kernel_stack = mm::vmstack::alloc().expect("Failed to allocate kernel stack for init")
        + task::percpu::KERNEL_STACK_SIZE as u64;

    // The per-CPU scheduler with its idle task, then pid 1 (the idle
    // tasks are tid 0, Linux swapper). ppid=0 (no parent), pgid=sid=0
    // like Linux's init_task (init/init_task.c); init calls setsid()
    // itself if it wants a session
    task::percpu::init();
    let init_tid = task::percpu::create_user_task(task::percpu::UserTaskConfig {
        ppid: 0, // init has no parent
        pgid: 0, // inherited from init_task, not a group leader
        sid: 0,  // not a session leader until setsid()
        kstack_top: kernel_stack,
        user_stack_top,
        page_table: user_pt,
    })
    .expect("Failed to create user task");

    // Schedulers for the APs, then the kernel threads: timer callbacks
    // (ktimers/N), the system workqueue worker, the per-CPU network
    // softnet threads. Then interrupts on: pid 1 may sleep from here.
    task::percpu::init_ap_schedulers();
    crate::timer::start_ktimers();
    crate::task::stop_machine::start();
    crate::workqueue::init();
    crate::net::start_threads();
    CurrentArch::enable_interrupts();

    // ========================================================================
    // Bus/Driver Model: Layered device discovery
    // ========================================================================
    //
    // Instead of hardcoding nested loops (PCI → xHCI → USB → USB-Serial),
    // we use a Linux-style bus/driver model:
    //
    // 1. Create BusManager and register buses
    // 2. Register drivers for each bus type
    // 3. BusManager enumerates root buses (PCI)
    // 4. PCI drivers (xHCI) create child buses (USB) when probed
    // 5. USB drivers (USB-Serial) are matched on the new USB bus
    // 6. The cascade continues automatically
    //
    // This is modular and extensible - no hardcoded loops needed!
    // ========================================================================

    use crate::bus::{BusManager, PciBus};
    use crate::net::driver::E1000PciDriver;
    use crate::usb::msc::{UsbMscBusDriver, UsbMscDeviceHandle};
    use crate::usb::{UsbSerialBusDriver, xhci::XhciPciDriver};
    use alloc::boxed::Box;

    // Create the bus manager
    let mut bus_manager = BusManager::new();

    // Let architecture register its platform bus and drivers
    CurrentArch::arch_bus_init(&mut bus_manager);

    // Register PCI bus (root bus)
    bus_manager.register_bus("pci", Box::new(PciBus::new()));

    // Register PCI drivers
    bus_manager.register_driver("pci", Box::new(XhciPciDriver));
    bus_manager.register_driver("pci", Box::new(E1000PciDriver));
    bus_manager.register_driver("pci", Box::new(crate::virtio::VirtioPciDriver));
    crate::virtio::register_driver(&crate::net::driver::virtio_net::VIRTIO_NET);
    crate::virtio::register_driver(&crate::virtio::blk::VIRTIO_BLK);

    // Register USB drivers (queued until USB bus is created by xHCI)
    bus_manager.register_driver("usb", Box::new(UsbSerialBusDriver));
    bus_manager.register_driver("usb", Box::new(UsbMscBusDriver));

    // Start the enumeration cascade:
    // Platform enumerate → PIC/PIT/Serial matched
    // PCI enumerate → xHCI matched → USB bus created → USB-Serial/USB-MSC matched
    bus_manager.enumerate_all(&mut frame_alloc);

    // SCSI disk (sda) from a USB MSC device, if present
    if let Some(handle) = bus_manager.find_device::<UsbMscDeviceHandle>() {
        let _ = crate::storage::create_scsi_disk(handle.scsi_host(), 0, 0);
    }

    // Kept for device_shutdown at power-off/restart
    crate::bus::bus::set_system_buses(bus_manager);

    // ========================================================================
    // Phase 5: VFS Initialization
    // ========================================================================
    init_vfs_core();

    // pid 1's root and working directory: the VFS exists now
    if let Some(fs) = crate::fs::FsStruct::new_root() {
        crate::fs::init_task_fs(init_tid, fs);
    }

    // Architecture-specific VFS extras (e.g., VFAT ramdisk from multiboot2 module on x86)
    CurrentArch::init_vfs_extras();

    // ========================================================================
    // Phase 6: Initramfs Unpacking
    // ========================================================================
    let initramfs_data = CurrentArch::get_initramfs();
    let root_dentry = crate::ns::init_mnt_ns()
        .get_root_dentry()
        .expect("VFS root not initialized");
    match fs::unpack_cpio(initramfs_data, &root_dentry) {
        Ok(n) => printkln!("initramfs: {} files", n),
        Err(e) => {
            printkln!("ERR: initramfs: {:?}", e);
            CurrentArch::halt_loop();
        }
    }

    // ========================================================================
    // Phase 6b: Graphics Console Initialization
    // ========================================================================
    // Initialize graphics console if framebuffer was discovered
    // This happens after VFS init so we can create /dev/dri if needed later
    unsafe {
        if gfx::console::init_graphics_console() {
            gfx::console::register_graphics_console();
        }
    }

    // ========================================================================
    // Phase 6c: DRM Subsystem Initialization
    // ========================================================================
    // Initialize DRM subsystem and SimpleDRM driver for Linux ABI compatibility
    gfx::init();
    if let Some(minor) = gfx::simplegfx::init_simplegfx() {
        printkln!("gfx: SimpleDRM device registered as card{}", minor);
    }

    printkln!("KERNEL_READY");

    // Run locking infrastructure self-tests
    crate::waitqueue::run_locking_tests();

    // The boot self-test
    crate::selftest::start();

    // stdin/stdout/stderr of init: /dev/console (Linux kernel_init)
    fs::open::console_on_rootfs();

    run_init()
}

/// Run the first user program in pid 1 (Linux init/main.c kernel_init):
/// `rdinit=` (default /init) if it exists, then `init=` (a failure is
/// fatal), then /sbin/init, /etc/init, /bin/init and /bin/sh. Each runs
/// through execve with argv {path, the command line's extra words} and
/// envp {HOME=/, TERM=linux, its extra name=value words}.
fn run_init() -> ! {
    let args = cmdline::init_args(&cmdline::saved());
    let rdinit = args.rdinit.as_deref().unwrap_or("/init");
    if fs::lookup_path(rdinit).is_ok() {
        let e = try_init(rdinit, &args);
        printkln!("Failed to execute {} (error {})", rdinit, e);
    }
    if let Some(init) = args.init.as_deref() {
        let e = try_init(init, &args);
        panic!("Requested init {} failed (error {}).", init, e);
    }
    for path in ["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"] {
        let e = try_init(path, &args);
        if e != -2 {
            printkln!(
                "Starting init: {} exists but couldn't execute it (error {})",
                path,
                e
            );
        }
    }
    panic!("No working init found.  Try passing init= option to kernel.");
}

/// execve `path` as init; returns only on failure, with the errno
fn try_init(path: &str, args: &cmdline::InitArgs) -> i32 {
    use alloc::vec::Vec;
    let mut argv: Vec<Vec<u8>> = alloc::vec![path.as_bytes().to_vec()];
    argv.extend(args.argv.iter().map(|a| a.as_bytes().to_vec()));
    let mut envp: Vec<Vec<u8>> = alloc::vec![b"HOME=/".to_vec(), b"TERM=linux".to_vec()];
    envp.extend(args.envp.iter().map(|e| e.as_bytes().to_vec()));
    let mut frame_alloc = frame_alloc::FrameAllocRef(&FRAME_ALLOCATOR);
    task::exec::do_execve(path.as_bytes().to_vec(), argv, envp, &mut frame_alloc)
}

/// Default RAM disk size in MB
const DEFAULT_RAMDISK_SIZE_MB: u64 = 8;

/// Initialize the core VFS with ramfs as root and procfs at /proc
///
/// This is the unified VFS initialization shared between architectures.
fn init_vfs_core() {
    use crate::chardev::DevId;
    use crate::storage::create_ramdisk;
    use fs::{PROCFS_TYPE, RAMFS_TYPE, do_mount, init_fs_registry, ramfs_create_dir};

    init_fs_registry();

    // Mount ramfs as root filesystem
    let root_mount = match do_mount(&RAMFS_TYPE, None) {
        Ok(m) => m,
        Err(e) => {
            printkln!("ERR: ramfs: {:?}", e);
            return;
        }
    };

    fs::DCACHE.set_root(root_mount.root.clone());

    // Create /proc and mount procfs
    let root_dentry = root_mount.root.clone();
    let proc_dentry = match ramfs_create_dir(&root_dentry, "proc") {
        Ok(d) => d,
        Err(_) => return,
    };
    let _ = do_mount(&PROCFS_TYPE, Some(proc_dentry));

    // Create /dev directory
    let dev_dentry = match ramfs_create_dir(&root_dentry, "dev") {
        Ok(d) => d,
        Err(_) => return,
    };

    // Register built-in character devices (null, zero)
    crate::chardev::register_builtin_chardevs();

    // Register TTY character devices (serial, etc.)
    crate::tty::init_tty_chardevs();

    // Device nodes: in devtmpfs, and the console's in the root's /dev
    // (opened for init before anything mounts devtmpfs; Linux needs
    // /dev/console in the initramfs)
    fs::devtmpfs::init();
    use crate::chardev::major as chardev_major;
    let mut nodes = alloc::vec![
        ("null", DevId::new(chardev_major::MEM, 3), 0o666),
        ("zero", DevId::new(chardev_major::MEM, 5), 0o666),
        ("full", DevId::new(chardev_major::MEM, 7), 0o666),
        ("random", DevId::new(chardev_major::MEM, 8), 0o666),
        ("urandom", DevId::new(chardev_major::MEM, 9), 0o666),
        ("kmsg", DevId::new(chardev_major::MEM, 11), 0o644),
        ("tty", DevId::new(chardev_major::TTYAUX, 0), 0o666),
        ("console", DevId::new(chardev_major::TTYAUX, 1), 0o666),
    ];
    if crate::chardev::get_chardev(DevId::new(chardev_major::TTYS, 64)).is_some() {
        nodes.push(("ttyS0", DevId::new(chardev_major::TTYS, 64), 0o666));
    }
    for (name, dev, mode) in nodes {
        let _ = fs::ramfs_create_chrdev(&dev_dentry, name, dev, mode);
        fs::devtmpfs::device_add(name, dev, false, mode);
    }

    // RAM disk rd0 (8MB)
    let _ = create_ramdisk(0, DEFAULT_RAMDISK_SIZE_MB);

    printkln!("VFS: ok");
}

/// Initialize VFAT ramdisk from multiboot2 module
///
/// This function:
/// 1. Loads the "vfat" multiboot2 module
/// 2. Creates a ramdisk (rd1) from the image data
/// 3. Creates /dev/rd1 device node
/// 4. Creates /vfat_test mount point
///
/// Note: The actual mount is performed by userspace init (boot_tester2)
/// via the mount syscall, simulating how real init/systemd works.
#[cfg(target_arch = "x86_64")]
pub fn init_vfat_ramdisk(
    root_dentry: &alloc::sync::Arc<fs::Dentry>,
    _dev_dentry: &alloc::sync::Arc<fs::Dentry>,
) {
    use crate::storage::create_ramdisk_from_data;
    use fs::ramfs_create_dir;

    // Look for vfat module loaded by bootloader
    let vfat_data = match unsafe { multiboot2::find_module(MULTIBOOT2_INFO, "vfat") } {
        Some(data) => data,
        None => return,
    };

    // Ramdisk rd1 from the vfat image data (node in devtmpfs)
    let _ = create_ramdisk_from_data(1, vfat_data);

    // Create /vfat_test mount point (userspace init will mount here)
    let _ = ramfs_create_dir(root_dentry, "vfat_test");
}

/// Panic handler (only for bare metal)
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts to prevent further issues
    CurrentArch::disable_interrupts();

    // Enable panic-safe printk (uses try_lock to avoid deadlock)
    crate::printk::set_oops_in_progress();

    printkln!("\n========================================");
    printkln!("!!! KERNEL PANIC !!!");
    printkln!("========================================");

    // Print CPU ID if available
    if let Some(cpu_id) = crate::cpu::try_this_id() {
        printkln!("CPU: {}", cpu_id);
    }

    // Print panic location
    if let Some(location) = info.location() {
        printkln!("Location: {}:{}", location.file(), location.line());
    }

    // Print panic message
    // Formatted messages (panic!("... {:#x}", v)) have no static str:
    // print through Display, or e.g. the faulting address is lost
    printkln!("Message: {}", info.message());

    // Architecture-specific register dump and backtrace
    #[cfg(target_arch = "x86_64")]
    {
        // Print basic register state
        let rsp: u64;
        let rbp: u64;
        let rflags: u64;
        unsafe {
            ::core::arch::asm!(
                "mov {}, rsp",
                "mov {}, rbp",
                "pushfq",
                "pop {}",
                out(reg) rsp,
                out(reg) rbp,
                out(reg) rflags,
                options(nomem, preserves_flags)
            );
        }
        printkln!("\nRegisters:");
        printkln!("  RSP: {:#018x}", rsp);
        printkln!("  RBP: {:#018x}", rbp);
        printkln!("  RFLAGS: {:#018x}", rflags);

        // Simple stack backtrace using frame pointers
        printkln!("\nStack backtrace:");
        let mut frame_ptr = rbp;
        let mut frame_count = 0;
        const MAX_FRAMES: usize = 16;

        while frame_ptr != 0 && frame_count < MAX_FRAMES {
            // Only follow frames on the current kernel stack: RBP may hold a
            // user value, and reading it would fault again under SMAP
            if !(rsp..rsp.saturating_add(0x10000)).contains(&frame_ptr) {
                break;
            }

            // Read return address (stored at frame_ptr + 8)
            let return_addr = unsafe { *((frame_ptr + 8) as *const u64) };
            if return_addr == 0 {
                break;
            }

            printkln!("  #{}: {:#018x}", frame_count, return_addr);

            // Move to previous frame
            let prev_frame = unsafe { *(frame_ptr as *const u64) };
            if prev_frame <= frame_ptr {
                // Prevent infinite loops
                break;
            }
            frame_ptr = prev_frame;
            frame_count += 1;
        }

        if frame_count == 0 {
            printkln!("  <no frames available>");
        }
    }

    // Print printk buffer stats
    let (used, total, overflow) = crate::printk::stats();
    printkln!(
        "\nPrintk buffer: {}/{} bytes{}",
        used,
        total,
        if overflow { " (OVERFLOW)" } else { "" }
    );

    printkln!("========================================");
    printkln!("System halted.");

    // Halt forever
    CurrentArch::halt_loop()
}

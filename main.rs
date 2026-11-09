//! hk kernel entry point
//!
//! This is the main kernel binary that ties together all components.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
// Auto-trait (Send/Sync) proofs of the object graph nest past the
// default 128 (a file's SIGIO owner holds a struct pid, which reaches
// the task graph)
#![recursion_limit = "256"]
// Host unit tests (`make test`) build only a subset; skip dead-code noise
#![cfg_attr(
    test,
    allow(
        dead_code,
        unused,
        reason = "host tests build kernel code they do not call"
    )
)]

extern crate alloc;

// Core modules (formerly in core/ subdir)
pub mod base;
pub mod block;
pub mod console;
pub mod cpu;
pub mod entry;
pub mod irq;
pub mod irq_stack;
mod ksysfs;
pub mod printk;
pub mod selftest;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod sysctl;
pub mod time;
pub mod uaccess;

// Device subsystems
pub mod dt;
pub mod gfx;
pub mod hw;
pub mod io;
pub mod net;
pub mod tty;
pub mod util;

// printkln macro is re-exported at crate root via #[macro_export]

// Multiboot2 header is in boot.S

mod arch;
pub mod bpf;
pub mod cgroup;
mod cmdline;
pub mod fs;
pub mod ipc;
pub mod keys;
mod kmsg;
pub mod mm;
pub mod ns;
mod power;
mod random;
pub mod seccomp;
pub mod signal;
pub mod task;

#[cfg(not(test))]
use ::core::panic::PanicInfo;

// Import architecture traits for trait method calls
use crate::arch::ArchBusOps;
use crate::arch::ArchPageTable;
use crate::arch::CurrentArch;
use crate::arch::{
    AcpiOps, CpuOps, ExceptionOps, HaltOps, InitramfsOps, LocalTimerOps, MemoryLayoutOps, PowerOps,
    SmpOps, TimekeeperOps, VfsInitOps,
};

use crate::hw::dma::{DirectDmaOps, dma_init};

#[expect(unused_imports)]
use fs::inode::AsAny; // Trait needed for .as_any() on dyn InodeData

/// Kernel heap: boot arena, then slab (host unit tests use the std
/// allocator)
#[cfg_attr(not(test), global_allocator)]
static ALLOCATOR: mm::heap::KernelAlloc = mm::heap::KernelAlloc::new();

/// Global frame allocator
static FRAME_ALLOCATOR: mm::frame_alloc::FrameAllocator = mm::frame_alloc::FrameAllocator::new();

/// Global DMA operations (direct mapping backend)
static DIRECT_DMA_OPS: DirectDmaOps = DirectDmaOps::new(&FRAME_ALLOCATOR);

use crate::mm::STACK_TOP as USER_STACK_TOP;

/// NUMA topology from firmware (ACPI SRAT/SLIT on x86-64, DT
/// numa-node-id on aarch64), else one node
fn init_numa_topology() {
    if CurrentArch::numa_init() {
        return;
    }
    let total_pages = mm::memblock::MEMBLOCK.lock().memory.total() / 4096;
    mm::numa::init_single_node_fallback(total_pages);
}

/// Discover the boot framebuffer from firmware (multiboot2 tag on
/// x86-64, DT simple-framebuffer on aarch64): stored in
/// BOOT_FRAMEBUFFER, its memory reserved
fn discover_boot_framebuffer() {
    use gfx::BOOT_FRAMEBUFFER;

    if let Some(info) = CurrentArch::boot_framebuffer() {
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
pub(crate) fn kmain() -> ! {
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

    // Initialize ioremap subsystem (MMIO virtual address management)
    crate::mm::ioremap::init();

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
    let mut frame_alloc = mm::frame_alloc::FrameAllocRef(&FRAME_ALLOCATOR);

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
        // SAFETY: the interrupt controller's registers from ACPI/DTB
        match unsafe { crate::mm::ioremap::ioremap(acpi_info.interrupt_controller_base, 4096) } {
            Err(e) => {
                printkln!("SMP: Failed to ioremap interrupt controller: {:?}", e);
            }
            Ok(ic_virt) => {
                // Initialize local interrupt controller
                // SAFETY: the controller just mapped, on the BSP, once
                unsafe {
                    CurrentArch::init_local_interrupt_controller(ic_virt as u64);
                }

                // Read BSP CPU ID and initialize SMP
                let bsp_id = CurrentArch::current_hw_cpu_id();
                CurrentArch::set_bsp_cpu_id(&mut acpi_info, bsp_id);

                let online = CurrentArch::smp_init(&acpi_info, &mut frame_alloc);
                smp::init(online as u32);
                // Every CPU has recorded its node (numa::cpu_up) by now
                mm::numa::print_topology();

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
    let Some(mut user_pt) = ArchPageTable::new_user(&mut frame_alloc) else {
        printkln!("ERR: page table alloc");
        CurrentArch::halt_loop();
    };
    user_pt.copy_kernel_mappings();
    // Its stack comes with the program exec loads into it (run_init)
    let user_stack_top = USER_STACK_TOP;
    // Kernel stack for PID 1 (init process), never freed
    let kernel_stack = mm::vmstack::alloc()
        .expect("Failed to allocate kernel stack for init")
        .leak()
        + task::percpu::KERNEL_STACK_SIZE as u64;

    // The per-CPU scheduler with its idle task, then pid 1 (the idle
    // tasks are tid 0, Linux swapper). ppid=0 (no parent), pgid=sid=0
    // like Linux's init_task (init/init_task.c); init calls setsid()
    // itself if it wants a session
    task::percpu::init();
    let init = task::percpu::create_user_task(task::percpu::UserTaskConfig {
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
    crate::time::timer::start_ktimers();
    crate::task::stop_machine::start();
    crate::task::workqueue::init();
    crate::net::start_threads();
    CurrentArch::enable_interrupts();

    // Linux order: mnt_init (start_kernel), then do_basic_setup:
    // driver_init (devtmpfs), core initcalls (ksysfs), fs initcalls
    // (chr_dev_init), then device initcalls (bus probes below)
    mnt_init();
    fs::ramfs::devtmpfs::init();
    base::driver_init();
    ksysfs::init();
    base::topology_init();
    net::sysfs::net_sysfs_init();
    chr_dev_init();

    // Device initcalls (Linux order: buses scanned, drivers registered,
    // each registration probing what it matches; a probe may register
    // child devices, probed in turn)
    block::genhd::genhd_init();
    CurrentArch::platform_init();
    hw::pci::pci_scan();
    hw::usb::usb_init();
    hw::usb::USB_SERIAL_DRIVER.register();
    hw::usb::msc::USB_STORAGE_DRIVER.register();
    hw::usb::xhci::XHCI_PCI_DRIVER.register();
    hw::net::E1000_DRIVER.register();
    hw::virtio::virtio_init();
    hw::virtio::VIRTIO_PCI_DRIVER.register();
    hw::net::virtio_net::VIRTIO_NET_DRIVER.register();
    hw::virtio::blk::VIRTIO_BLK_DRIVER.register();

    // RAM disk rd0 (Linux brd_init, a device initcall)
    let _ = crate::block::create_ramdisk(0, DEFAULT_RAMDISK_SIZE_MB);

    // pid 1's root and working directory: the VFS exists now
    if let Some(fs) = crate::fs::FsStruct::new_root() {
        crate::fs::init_task_fs(&init, fs);
    }

    // Architecture-specific VFS extras (e.g., VFAT ramdisk from multiboot2 module on x86)
    CurrentArch::init_vfs_extras();

    // ========================================================================
    // Phase 6: Initramfs Unpacking
    // ========================================================================
    let initrd = CurrentArch::get_initramfs();
    let root_dentry = crate::ns::init_mnt_ns()
        .root_path()
        .expect("VFS root not initialized")
        .dentry
        .clone();
    match fs::ramfs::cpio::unpack_cpio(initrd.data(), &root_dentry) {
        Ok(n) => printkln!("initramfs: {} files", n),
        Err(e) => {
            printkln!("ERR: initramfs: {:?}", e);
            CurrentArch::halt_loop();
        }
    }
    // Everything was copied out (Linux do_populate_rootfs)
    initrd.free();

    // ========================================================================
    // Phase 6b: Graphics Console Initialization
    // ========================================================================
    // Initialize graphics console if framebuffer was discovered
    // This happens after VFS init so we can create /dev/dri if needed later
    // SAFETY: once, at boot, after ioremap is up (its contract)
    unsafe {
        if hw::gfx::console::init_graphics_console() {
            hw::gfx::console::register_graphics_console();
        }
    }

    // ========================================================================
    // Phase 6c: DRM Subsystem Initialization
    // ========================================================================
    // Initialize DRM subsystem and SimpleDRM driver for Linux ABI compatibility
    gfx::init();
    if let Some(minor) = hw::gfx::simplegfx::init_simplegfx() {
        printkln!("gfx: SimpleDRM device registered as card{}", minor);
    }

    printkln!("KERNEL_READY");

    // Run locking infrastructure self-tests
    crate::sync::waitqueue::run_locking_tests();

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
    if fs::lookup_path(rdinit.as_bytes()).is_ok() {
        let e = try_init(rdinit, &args);
        printkln!("Failed to execute {} (error {})", rdinit, e.to_errno_neg());
    }
    if let Some(init) = args.init.as_deref() {
        let e = try_init(init, &args);
        panic!(
            "Requested init {} failed (error {}).",
            init,
            e.to_errno_neg()
        );
    }
    for path in ["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"] {
        let e = try_init(path, &args);
        if e != util::error::KernelError::NotFound {
            printkln!(
                "Starting init: {} exists but couldn't execute it (error {})",
                path,
                e.to_errno_neg()
            );
        }
    }
    panic!("No working init found.  Try passing init= option to kernel.");
}

/// execve `path` as init; returns only on failure, with its error
fn try_init(path: &str, args: &cmdline::InitArgs) -> util::error::KernelError {
    use task::exec::ArgStrings;
    let mut argv = ArgStrings::new();
    let mut envp = ArgStrings::new();
    let args_ok = core::iter::once(path)
        .chain(args.argv.iter().map(|a| a.as_ref()))
        .try_for_each(|a| argv.push(a.as_bytes()))
        .and_then(|()| {
            ["HOME=/", "TERM=linux"]
                .into_iter()
                .chain(args.envp.iter().map(|e| e.as_ref()))
                .try_for_each(|e| envp.push(e.as_bytes()))
        });
    if let Err(e) = args_ok {
        return e;
    }
    let mut frame_alloc = mm::frame_alloc::FrameAllocRef(&FRAME_ALLOCATOR);
    match task::exec::do_execve(path.as_bytes().to_vec(), argv, envp, &mut frame_alloc) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

/// Default RAM disk size in MB
const DEFAULT_RAMDISK_SIZE_MB: u64 = 8;

/// The VFS core (Linux mnt_init): filesystem types, kernfs/sysfs, the
/// mount tree with /dev
fn mnt_init() {
    use fs::{init_fs_registry, ramfs_create_dir};

    init_fs_registry();
    fs::kernfs::sysfs::init();
    // The kernel's tmpfs (Linux shmem_init, before init_rootfs and
    // init_mount_tree)
    if let Err(e) = fs::ramfs::tmpfs::shmem_init() {
        printkln!("ERR: tmpfs: {:?}", e);
    }
    let root_mount = match fs::mount::init_mount_tree() {
        Ok(m) => m,
        Err(e) => {
            printkln!("ERR: rootfs: {:?}", e);
            return;
        }
    };
    fs::DCACHE.set_root(root_mount.root.clone());
    let _ = ramfs_create_dir(&root_mount.root, b"dev");
}

/// Memory and tty character devices (Linux chr_dev_init, fs_initcall)
fn chr_dev_init() {
    use crate::fs::chardev::DevId;

    crate::fs::chardev::register_builtin_chardevs();

    // Linux chr_dev_init ends in tty_init
    crate::tty::init_tty_chardevs();

    // The rootfs's /dev/console, opened for init before anything mounts
    // devtmpfs (Linux default_rootfs)
    if let Ok(dev) = fs::lookup_path(b"/dev") {
        let console = DevId::new(crate::fs::chardev::major::TTYAUX, 1);
        let _ = fs::ramfs_create_chrdev(&dev, b"console", console, 0o600);
    }

    printkln!("VFS: ok");
}

/// Panic handler (only for bare metal)
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
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
    CurrentArch::dump_stack();

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

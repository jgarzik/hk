//! hk kernel entry point
//!
//! This is the main kernel binary that ties together all components.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

// Core modules (formerly in core/ subdir)
pub mod bus;
pub mod chardev;
pub mod console;
pub mod dma;
pub mod elf;
pub mod epoll;
pub mod eventfd;
pub mod futex;
pub mod inotify;
pub mod io_uring;
pub mod kcmp;
pub mod pidfd;
pub mod pipe;
pub mod poll;
pub mod posix_timer;
pub mod printk;
pub mod signalfd;
pub mod storage;
mod time;
pub mod timer;
pub mod timerfd;
pub mod uaccess;
pub mod waitqueue;
pub mod workqueue;

// Device subsystems
pub mod dt;
pub mod gfx;
pub mod net;
pub mod tty;
pub mod usb;

// printkln macro is re-exported at crate root via #[macro_export]

// Multiboot2 header is in boot.S

mod arch;
mod cmdline;
mod frame_alloc;
pub mod fs;
mod heap;
pub mod ipc;
pub mod keys;
pub mod membarrier;
pub mod mm;
#[cfg(target_arch = "x86_64")]
mod multiboot2;
pub mod ns;
mod power;
mod random;
mod rlimit;
pub mod signal;
pub mod task;
mod time_syscall;

use ::core::panic::PanicInfo;

// Architecture type alias for generic kernel code
#[cfg(target_arch = "x86_64")]
type CurrentArch = crate::arch::x86_64::X86_64Arch;

#[cfg(target_arch = "aarch64")]
type CurrentArch = crate::arch::aarch64::Aarch64Arch;

// Import architecture traits for trait method calls
use crate::arch::ArchBusOps;
use crate::arch::{
    AcpiOps, CpuOps, EarlyArchInit, ExceptionOps, HaltOps, InitramfsOps, IoremapOps, LocalTimerOps,
    MemoryLayoutOps, PerCpuOps, PowerOps, SmpOps, TimekeeperOps, TimerCallbackOps, VfsInitOps,
    phys_to_virt,
};
use crate::arch::{SchedArch, SyscallOps, UserModeOps};

// Page table type alias (used by ELF loading)
type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

use heap::HeapAllocator;

use crate::dma::{DirectDmaOps, dma_init};
use crate::mm::page_cache::{FileId, NULL_AOPS, PAGE_SIZE as PC_PAGE_SIZE, PageCache};

#[allow(unused_imports)]
use fs::inode::AsAny; // Trait needed for .as_any() on dyn InodeData

use spin::Mutex;

// Memory layout constants - x86_64
// NOTE: Heap must not overlap with multiboot2 modules loaded at ~0x200000-0x400000
#[cfg(target_arch = "x86_64")]
const KERNEL_HEAP_START: usize = 0x400000; // 4MB (above multiboot modules)
#[cfg(target_arch = "x86_64")]
const KERNEL_HEAP_SIZE: usize = 0xE00000; // 14MB (up to 18MB where frame allocator starts)

// Memory layout constants - aarch64
// QEMU virt machine loads kernel at 0x40000000
// We place heap after the kernel image (starting at 0x40800000 = kernel + 8MB)
#[cfg(target_arch = "aarch64")]
const KERNEL_HEAP_START: usize = 0x4080_0000; // 8MB after kernel load
#[cfg(target_arch = "aarch64")]
const KERNEL_HEAP_SIZE: usize = 0x0100_0000; // 16MB

/// Kernel heap allocator
#[global_allocator]
static ALLOCATOR: HeapAllocator = HeapAllocator::new();

/// Global page cache (1024 pages = 4MB max)
static PAGE_CACHE: Mutex<PageCache> = Mutex::new(PageCache::new(1024));

/// Global frame allocator
static FRAME_ALLOCATOR: frame_alloc::BitmapFrameAllocator =
    frame_alloc::BitmapFrameAllocator::new();

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
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn _start(multiboot_info: u64) -> ! {
    // Save multiboot info for later use
    unsafe {
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

    // Initialize heap allocator
    unsafe {
        ALLOCATOR.init(KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
    }

    // Initialize architecture-specific code (GDT, IDT, PIC, PIT)
    CurrentArch::early_init();

    // Continue to main kernel
    kmain()
}

/// AArch64 Kernel entry point called from boot.S
///
/// dtb_ptr: Pointer to Device Tree Blob (passed in x0)
#[cfg(target_arch = "aarch64")]
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

    // Find DTB in memory (QEMU virt ELF boot places DTB at RAM start)
    {
        const DTB_MAGIC_BE: u32 = 0xd00dfeed;
        let ram_end = 0x6000_0000u64;
        let kernel_end = 0x4200_0000u64;

        let specific_addrs: [u64; 4] = [0x4000_0000, 0x4008_0000, 0x4400_0000, 0x4800_0000];
        let mut found_dtb = false;
        for &addr in &specific_addrs {
            let magic = unsafe { ::core::ptr::read_volatile(addr as *const u32) };
            if magic.swap_bytes() == DTB_MAGIC_BE {
                unsafe {
                    DTB_PTR = addr;
                }
                found_dtb = true;
                break;
            }
        }

        if !found_dtb {
            let mut scan_addr = kernel_end;
            while scan_addr < ram_end {
                let magic = unsafe { ::core::ptr::read_volatile(scan_addr as *const u32) };
                if magic.swap_bytes() == DTB_MAGIC_BE {
                    unsafe {
                        DTB_PTR = scan_addr;
                    }
                    break;
                }
                scan_addr += 0x1000;
            }
        }
    }

    // Initialize architecture (CPU features, RTC, etc.)
    CurrentArch::early_init();

    // Initialize page tables and enable MMU
    unsafe {
        crate::arch::aarch64::init_mmu();
    }

    // Initialize heap allocator
    unsafe {
        ALLOCATOR.init(KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
    }

    // Extract and parse kernel command line from DTB /chosen/bootargs
    if let Some(cmdline) = crate::arch::aarch64::dtb::extract_bootargs(dtb_ptr as *const u8)
        && !cmdline.is_empty()
    {
        printkln!("Cmdline: {}", cmdline);
        cmdline::parse_cmdline(cmdline);
    }

    // Continue to unified main kernel
    kmain()
}

// ELF loading constants - shared by both architectures
const PAGE_SIZE: u64 = 4096;
const USER_STACK_PAGES: usize = 4;

// x86_64: User stack at top of lower half of 48-bit VA space
#[cfg(target_arch = "x86_64")]
const USER_STACK_TOP: u64 = 0x7FFF_FFFF_F000;
// aarch64: User stack at top of TTBR0 range (just under 512GB for QEMU virt)
#[cfg(target_arch = "aarch64")]
const USER_STACK_TOP: u64 = 0x7FFF_FFFF_F000; // Same as x86 for simplicity

// PIE base address - where position-independent executables load
#[cfg(target_arch = "x86_64")]
const USER_PIE_BASE: u64 = 0x20000000;
#[cfg(target_arch = "aarch64")]
const USER_PIE_BASE: u64 = 0x8000_0000; // Above the 2GB kernel identity-mapped region

fn load_elf_with_cache<PT, FA>(
    elf: &crate::elf::ElfExecutable<u64>,
    file_id: FileId,
    elf_data: &[u8],
    page_table: &mut PT,
    frame_alloc: &mut FA,
    base_addr: u64,
) -> Result<(), &'static str>
where
    PT: crate::arch::PageTable<VirtAddr = u64, PhysAddr = u64>,
    FA: crate::arch::FrameAlloc<PhysAddr = u64>,
{
    use crate::arch::PageFlags;

    // Track which virtual pages we've already mapped
    let mut mapped_pages: [(u64, u64); 32] = [(0, 0); 32];
    let mut mapped_count = 0;

    for segment in &elf.segments {
        if segment.mem_size == 0 {
            continue;
        }

        // Add base address for PIE binaries
        let seg_start = segment.vaddr + base_addr;
        let seg_end = segment.vaddr + base_addr + segment.mem_size as u64;
        let page_start = seg_start & !(PAGE_SIZE - 1);
        let page_end = (seg_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Convert ELF flags to PageFlags
        let mut flags = PageFlags::READ | PageFlags::USER;
        if segment.flags.write {
            flags |= PageFlags::WRITE;
        }
        if segment.flags.execute {
            flags |= PageFlags::EXECUTE;
        }

        let mut va = page_start;
        while va < page_end {
            // Check if already mapped
            let existing = mapped_pages[..mapped_count]
                .iter()
                .find(|(v, _)| *v == va)
                .map(|(_, f)| *f);

            let frame = if let Some(f) = existing {
                f
            } else {
                // Calculate the file offset for this page
                let page_va_offset = va.saturating_sub(seg_start);
                let file_page_offset = (segment.offset + page_va_offset) / PC_PAGE_SIZE as u64;

                let f = if segment.flags.write {
                    // Writable segment: must have private copy
                    let private_frame = frame_alloc
                        .alloc_frame()
                        .ok_or("Out of memory for writable segment")?;

                    // Zero the frame first
                    unsafe {
                        ::core::ptr::write_bytes(private_frame as *mut u8, 0, PAGE_SIZE as usize);
                    }

                    // Try to get data from cache or directly from file
                    let cache = PAGE_CACHE.lock();
                    if let Some(cached_page) = cache.find_get_page(file_id, file_page_offset) {
                        // Copy from cached page
                        unsafe {
                            ::core::ptr::copy_nonoverlapping(
                                cached_page.frame as *const u8,
                                private_frame as *mut u8,
                                PC_PAGE_SIZE,
                            );
                        }
                        cache.put_page(&cached_page);
                    } else {
                        // Cache miss for writable - copy directly from file
                        let file_offset = file_page_offset * PC_PAGE_SIZE as u64;
                        if (file_offset as usize) < elf_data.len() {
                            let copy_len = ::core::cmp::min(
                                PC_PAGE_SIZE,
                                elf_data.len() - file_offset as usize,
                            );
                            unsafe {
                                ::core::ptr::copy_nonoverlapping(
                                    elf_data.as_ptr().add(file_offset as usize),
                                    private_frame as *mut u8,
                                    copy_len,
                                );
                            }
                        }
                    }

                    private_frame
                } else {
                    // Read-only segment: can share cached pages
                    let mut cache = PAGE_CACHE.lock();

                    // Try cache lookup first
                    let cached = if let Some(page) = cache.find_get_page(file_id, file_page_offset)
                    {
                        page
                    } else {
                        // Cache miss: add to cache
                        cache
                            .add_page(
                                file_id,
                                file_page_offset,
                                elf_data,
                                elf_data.len() as u64,
                                frame_alloc,
                                true,  // can_writeback: ELF pages are read-only, evictable
                                false, // not unevictable (ELF pages can be re-read)
                                &NULL_AOPS,
                            )
                            .map_err(|_| "Failed to add page to cache")?
                    };

                    cached.frame
                };

                // Map the page
                page_table
                    .map_with_alloc(va, f, flags, frame_alloc)
                    .map_err(|_| "Failed to map ELF page")?;

                // Track mapping
                if mapped_count < mapped_pages.len() {
                    mapped_pages[mapped_count] = (va, f);
                    mapped_count += 1;
                }

                f
            };

            // For pages that span segment boundaries or have BSS, we may need
            // additional handling. The cache pre-zeros frames, so BSS is covered.
            let _ = frame; // suppress unused warning

            va += PAGE_SIZE;
        }
    }

    // Log cache stats
    let (cached, max) = PAGE_CACHE.lock().stats();
    printkln!("Page cache: {}/{} pages", cached, max);

    Ok(())
}

/// Apply ELF relocations for PIE binaries
///
/// For R_*_RELATIVE relocations: *(base + offset) = base + addend
fn apply_relocations<PT>(elf: &crate::elf::ElfExecutable<u64>, base_addr: u64, page_table: &PT)
where
    PT: crate::arch::PageTable<VirtAddr = u64, PhysAddr = u64>,
{
    for reloc in &elf.relocations {
        let target_vaddr = base_addr + reloc.offset;
        let value = (base_addr as i64 + reloc.addend) as u64;

        // Look up the physical address for this virtual address
        if let Some(phys) = page_table.translate(target_vaddr) {
            // Write the relocated value to physical memory
            unsafe {
                let ptr = phys_to_virt(phys) as *mut u64;
                ::core::ptr::write_volatile(ptr, value);
            }
        }
    }

    if !elf.relocations.is_empty() {
        printkln!("Applied {} relocations", elf.relocations.len());
    }
}

/// Allocate user stack pages
///
/// Returns the stack top (highest address, stack grows down).
fn allocate_user_stack<PT, FA>(
    page_table: &mut PT,
    frame_alloc: &mut FA,
) -> Result<u64, &'static str>
where
    PT: crate::arch::PageTable<VirtAddr = u64, PhysAddr = u64>,
    FA: crate::arch::FrameAlloc<PhysAddr = u64>,
{
    use crate::arch::PageFlags;

    let stack_bottom = USER_STACK_TOP - (USER_STACK_PAGES as u64 * PAGE_SIZE);
    let flags = PageFlags::READ | PageFlags::WRITE | PageFlags::USER;

    for i in 0..USER_STACK_PAGES {
        let va = stack_bottom + (i as u64 * PAGE_SIZE);

        // Allocate a physical frame
        let frame = frame_alloc
            .alloc_frame()
            .ok_or("Out of memory allocating stack frame")?;

        // Zero the frame
        unsafe {
            ::core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }

        // Map the page
        page_table
            .map_with_alloc(va, frame, flags, frame_alloc)
            .map_err(|_| "Failed to map stack page")?;
    }

    Ok(USER_STACK_TOP)
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

        // Reserve framebuffer memory so frame allocator doesn't use it
        FRAME_ALLOCATOR.mark_used(info.phys_addr, info.size);

        // Store for later use by graphics subsystem
        BOOT_FRAMEBUFFER.call_once(|| info);
    }
}

/// Main kernel function (unified for all architectures)
fn kmain() -> ! {
    // ========================================================================
    // Phase 1: Memory Subsystem
    // ========================================================================

    // Get memory layout from arch (multiboot2 on x86, DTB/hardcoded on arm)
    let (alloc_base, alloc_size) = CurrentArch::get_frame_alloc_region();
    printkln!("MEM: {} MB", alloc_size / (1024 * 1024));

    // Initialize frame allocator
    FRAME_ALLOCATOR.init(alloc_base, alloc_size);
    FRAME_ALLOCATOR.mark_used(0, alloc_base);

    // Initialize DMA subsystem (uses frame allocator)
    dma_init(&DIRECT_DMA_OPS);

    // Run page cache self-tests (verifies locking correctness)
    crate::mm::page_cache::run_self_tests();

    // Initialize ioremap subsystem (MMIO virtual address management)
    CurrentArch::ioremap_init();

    // ========================================================================
    // Phase 1b: Graphics Framebuffer Discovery
    // ========================================================================
    // Discover boot framebuffer from firmware (multiboot2 on x86, DTB on arm)
    // This must happen after ioremap_init but before we heavily use the frame allocator
    discover_boot_framebuffer();

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

                // Set up timer preemption callback
                unsafe {
                    CurrentArch::set_timer_preempt_callback(task::percpu::maybe_preempt);
                }

                // Enable APs to start their timers and participate in scheduling
                CurrentArch::enable_ap_scheduling();
            }
        }
    } else {
        printkln!("SMP: Platform discovery failed (ACPI/device tree)");
    }

    // Initialize platform drivers (legacy registry)
    let mut driver_registry = crate::bus::DriverRegistry::new();
    crate::bus::register_drivers(&mut driver_registry);

    // Initialize network subsystem (sets up loopback, static IP config)
    crate::net::init();

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

    // Register USB drivers (queued until USB bus is created by xHCI)
    bus_manager.register_driver("usb", Box::new(UsbSerialBusDriver));
    bus_manager.register_driver("usb", Box::new(UsbMscBusDriver));

    // Start the enumeration cascade:
    // Platform enumerate → PIC/PIT/Serial matched
    // PCI enumerate → xHCI matched → USB bus created → USB-Serial/USB-MSC matched
    bus_manager.enumerate_all(&mut frame_alloc);

    // Create SCSI disk from USB MSC device if present
    let scsi_disk_created = if let Some(handle) = bus_manager.find_device::<UsbMscDeviceHandle>() {
        let scsi_host = handle.scsi_host();
        match crate::storage::create_scsi_disk(scsi_host, 0, 0, 0) {
            Ok(bdev) => {
                ::core::mem::forget(bdev);
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };

    // ========================================================================
    // Phase 5: VFS Initialization
    // ========================================================================
    init_vfs_core();

    // Architecture-specific VFS extras (e.g., VFAT ramdisk from multiboot2 module on x86)
    CurrentArch::init_vfs_extras();

    // ========================================================================
    // Phase 6: Initramfs Unpacking
    // ========================================================================
    let initramfs_data = CurrentArch::get_initramfs();
    let root_dentry = fs::init_mnt_ns()
        .get_root_dentry()
        .expect("VFS root not initialized");
    match fs::unpack_cpio(initramfs_data, &root_dentry) {
        Ok(n) => printkln!("initramfs: {} files", n),
        Err(e) => {
            printkln!("ERR: initramfs: {:?}", e);
            CurrentArch::halt_loop();
        }
    }

    // Create /dev/sd0 device node if SCSI disk was created
    if scsi_disk_created {
        let dev_dentry = fs::lookup_path("/dev").expect("/dev must exist");
        let rdev = crate::storage::DevId::new(crate::storage::major::SCSI_DISK, 0);
        let _ = fs::ramfs::ramfs_create_blkdev(&dev_dentry, "sd0", rdev, 0o660);
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

    // Register syscall handler
    CurrentArch::set_syscall_handler(CurrentArch::syscall_dispatcher());

    // Load /bin/init from ramfs via VFS
    let init_dentry = match fs::lookup_path("/bin/init") {
        Ok(d) => d,
        Err(e) => {
            printkln!("ERROR: /bin/init not found: {:?}", e);
            CurrentArch::halt_loop();
        }
    };
    let init_inode = init_dentry.get_inode().expect("/bin/init has no inode");

    // Get file_id from ramfs inode for page cache access
    let private = init_inode
        .get_private()
        .expect("/bin/init has no private data");
    let ramfs_data = private
        .as_ref()
        .as_any()
        .downcast_ref::<fs::RamfsInodeData>()
        .expect("/bin/init is not a ramfs file");
    let file_id = ramfs_data.file_id.expect("/bin/init has no file_id");
    let file_size = init_inode.get_size() as usize;

    // Read entire file from page cache into buffer
    let mut init_data_vec = alloc::vec![0u8; file_size];
    {
        let mut bytes_read = 0;
        while bytes_read < file_size {
            let page_offset = (bytes_read / PC_PAGE_SIZE) as u64;
            let offset_in_page = bytes_read % PC_PAGE_SIZE;
            let chunk_size =
                ::core::cmp::min(PC_PAGE_SIZE - offset_in_page, file_size - bytes_read);

            // Get page from cache (pages should exist since file was populated at boot)
            let page = {
                let mut cache = PAGE_CACHE.lock();
                let (page, _) = cache
                    .find_or_create_page(
                        file_id,
                        page_offset,
                        file_size as u64,
                        &mut frame_alloc,
                        false,      // can_writeback
                        true,       // unevictable (ramfs pages)
                        &NULL_AOPS, // Generic ops - page should already exist
                    )
                    .expect("Failed to get page for /bin/init");
                page
            };

            // Copy from page to buffer
            unsafe {
                ::core::ptr::copy_nonoverlapping(
                    (page.frame as *const u8).add(offset_in_page),
                    init_data_vec[bytes_read..].as_mut_ptr(),
                    chunk_size,
                );
            }

            bytes_read += chunk_size;
        }
    }
    let init_bytes: &[u8] = &init_data_vec;

    // Parse ELF header
    fn addr_from_u64(v: u64) -> u64 {
        v
    }
    let elf = match crate::elf::ElfExecutable::<u64>::parse(init_bytes, addr_from_u64) {
        Ok(e) => e,
        Err(_) => {
            printkln!("ERR: ELF parse failed");
            CurrentArch::halt_loop();
        }
    };
    printkln!("ELF: entry=0x{:x}", elf.entry);

    // Create user page table
    let mut user_pt = match ArchPageTable::new_user(&mut frame_alloc) {
        Some(pt) => pt,
        None => {
            printkln!("ERR: page table alloc");
            CurrentArch::halt_loop();
        }
    };
    user_pt.copy_kernel_mappings();

    // Load ELF segments into user page table using page cache
    let base_addr = if elf.is_pie { USER_PIE_BASE } else { 0 };
    if let Err(e) = load_elf_with_cache(
        &elf,
        file_id,
        init_bytes,
        &mut user_pt,
        &mut frame_alloc,
        base_addr,
    ) {
        printkln!("ERR: {}", e);
        CurrentArch::halt_loop();
    }

    // Apply relocations for PIE binaries
    apply_relocations(&elf, base_addr, &user_pt);

    // Calculate highest segment end for brk initialization
    let mut highest_end: u64 = 0;
    for segment in &elf.segments {
        if segment.mem_size > 0 {
            let seg_end = segment.vaddr + base_addr + segment.mem_size as u64;
            if seg_end > highest_end {
                highest_end = seg_end;
            }
        }
    }
    // Page-align to get start_brk
    let start_brk = (highest_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Allocate user stack
    let user_stack_top = match allocate_user_stack(&mut user_pt, &mut frame_alloc) {
        Ok(sp) => sp,
        Err(e) => {
            printkln!("ERR: {}", e);
            CurrentArch::halt_loop();
        }
    };

    // Allocate kernel stack for PID 1 (init process)
    let kernel_stack = {
        use crate::arch::FrameAlloc;
        const INIT_KERNEL_STACK_SIZE: usize = 16 * 1024;
        const FRAME_SIZE: usize = 4096;
        let stack_pages = INIT_KERNEL_STACK_SIZE / FRAME_SIZE;
        let mut stack_base: Option<u64> = None;

        for i in 0..stack_pages {
            let frame = frame_alloc
                .alloc_frame()
                .expect("Failed to allocate kernel stack for init");
            if i == 0 {
                stack_base = Some(frame);
            }
            unsafe {
                ::core::ptr::write_bytes(frame as *mut u8, 0, FRAME_SIZE);
            }
        }

        stack_base.unwrap() + INIT_KERNEL_STACK_SIZE as u64
    };

    printkln!("KERNEL_READY");

    // Run locking infrastructure self-tests
    crate::waitqueue::run_locking_tests();

    // Calculate actual entry point (add base for PIE)
    let entry_point = elf.entry + base_addr;

    // Initialize the per-CPU scheduler with idle task
    // This must be done before creating the user task
    task::percpu::init(&mut frame_alloc);

    // Register user task with scheduler (pid=1, tid=2)
    // Note: idle task has tid=1, pid=0 (kernel swapper convention)
    // Init process: ppid=0 (no parent), pgid=1 (own group), sid=1 (session leader)
    // Save the page table root before moving user_pt
    let page_table_root = user_pt.root_table_phys();

    task::percpu::create_user_task(task::percpu::UserTaskConfig {
        pid: 1,  // init process (PID 1)
        tid: 2,  // tid=2 since idle task has tid=1
        ppid: 0, // init has no parent
        pgid: 1, // init is its own process group leader
        sid: 1,  // init is the session leader
        priority: task::PRIORITY_NORMAL,
        kstack_top: kernel_stack,
        user_stack_top,
        page_table: user_pt,
    })
    .expect("Failed to create user task");

    // Initialize brk for the init task (tid=2)
    // This must be done after create_user_task which creates a default mm
    if let Some(mm) = mm::get_task_mm(2) {
        mm.lock().set_brk(start_brk);
    }

    // Enable scheduling
    task::percpu::enable();

    // Set per-CPU current task state
    // tid=2, pid=1, ppid=0, pgid=1, sid=1 (init process)
    task::percpu::set_current_task(2, 1, 0, 1, 1, task::Cred::ROOT);

    // Jump to user mode!
    // This never returns.
    //
    // Note: x86-64 ABI requires RSP to be 8 bytes below 16-byte alignment at function entry
    // (because 'call' would push an 8-byte return address). Since we're entering via IRET
    // not CALL, we need to subtract 8 from the stack top to maintain ABI alignment.
    let user_sp = user_stack_top - 8;

    // ARM64: Final cache flush barrier before jumping to user mode.
    // The ELF segments were cache-flushed earlier, but between then and now
    // we've done a lot of kernel operations. This ensures all cache operations
    // are truly visible before the ERET to user mode.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb sy", // Full system data synchronization barrier
            "isb",    // Instruction synchronization barrier
            options(nostack, preserves_flags)
        );
    }

    unsafe {
        CurrentArch::jump_to_user(entry_point, user_sp, page_table_root, kernel_stack);
    }
}

/// Default RAM disk size in MB
const DEFAULT_RAMDISK_SIZE_MB: u64 = 8;

/// Initialize the core VFS with ramfs as root and procfs at /proc
///
/// This is the unified VFS initialization shared between architectures.
fn init_vfs_core() {
    use crate::chardev::DevId;
    use crate::storage::create_ramdisk;
    use crate::storage::major;
    use fs::{
        PROCFS_TYPE, RAMFS_TYPE, do_mount, init_fs_registry, ramfs_create_blkdev, ramfs_create_dir,
    };

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

    // Create character device nodes in /dev
    use crate::chardev::major as chardev_major;

    // /dev/null (major 1, minor 3)
    let _ = fs::ramfs_create_chrdev(
        &dev_dentry,
        "null",
        DevId::new(chardev_major::MEM, 3),
        0o666,
    );

    // /dev/zero (major 1, minor 5)
    let _ = fs::ramfs_create_chrdev(
        &dev_dentry,
        "zero",
        DevId::new(chardev_major::MEM, 5),
        0o666,
    );

    // /dev/ttyS0 (major 4, minor 64) - only create if TTY is registered
    if crate::chardev::get_chardev(DevId::new(chardev_major::TTYS, 64)).is_some() {
        let _ = fs::ramfs_create_chrdev(
            &dev_dentry,
            "ttyS0",
            DevId::new(chardev_major::TTYS, 64),
            0o666,
        );
    }

    // /dev/tty (major 5, minor 0) - controlling terminal
    let _ = fs::ramfs_create_chrdev(
        &dev_dentry,
        "tty",
        DevId::new(chardev_major::TTYAUX, 0),
        0o666,
    );

    // /dev/console (major 5, minor 1) - kernel console
    let _ = fs::ramfs_create_chrdev(
        &dev_dentry,
        "console",
        DevId::new(chardev_major::TTYAUX, 1),
        0o666,
    );

    // Create RAM disk rd0 (8MB)
    if let Ok(_bdev) = create_ramdisk(0, DEFAULT_RAMDISK_SIZE_MB) {
        let rdev = DevId::new(major::RAMDISK, 0);
        let _ = ramfs_create_blkdev(&dev_dentry, "rd0", rdev, 0o660);
    }

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
    dev_dentry: &alloc::sync::Arc<fs::Dentry>,
) {
    use crate::chardev::DevId;
    use crate::storage::create_ramdisk_from_data;
    use crate::storage::major;
    use fs::{ramfs_create_blkdev, ramfs_create_dir};

    // Look for vfat module loaded by bootloader
    let vfat_data = match unsafe { multiboot2::find_module(MULTIBOOT2_INFO, "vfat") } {
        Some(data) => data,
        None => return,
    };

    // Create ramdisk rd1 from the vfat image data
    if create_ramdisk_from_data(1, vfat_data).is_ok() {
        let rdev = DevId::new(major::RAMDISK, 1);
        let _ = ramfs_create_blkdev(dev_dentry, "rd1", rdev, 0o660);
    }

    // Create /vfat_test mount point (userspace init will mount here)
    let _ = ramfs_create_dir(root_dentry, "vfat_test");
}

/// Panic handler (only for bare metal)
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
    if let Some(cpu_id) = CurrentArch::try_current_cpu_id() {
        printkln!("CPU: {}", cpu_id);
    }

    // Print panic location
    if let Some(location) = info.location() {
        printkln!("Location: {}:{}", location.file(), location.line());
    }

    // Print panic message
    if let Some(message) = info.message().as_str() {
        printkln!("Message: {}", message);
    } else {
        printkln!("Message: <no message>");
    }

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
            // Validate frame pointer (must be in reasonable kernel range)
            if !(0x1000..=0xFFFF_FFFF_FFFF_0000).contains(&frame_ptr) {
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

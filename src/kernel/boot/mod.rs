// src/kernel/boot/mod.rs
#![no_std]
#![no_main]
#![feature(asm)]

use bootloader_api::{entry_point, BootInfo};
use core::arch::asm;
use core::panic::PanicInfo;
use spin::Mutex;

// Global kernel state
pub static KERNEL_STATE: Mutex<KernelState> = Mutex::new(KernelState::new());

#[derive(Debug)]
pub struct KernelState {
    boot_flags: u64,
    memory_map: Option<MemoryMap>,
    cpu_info: CpuInfo,
    initialized: bool,
}

impl KernelState {
    const fn new() -> Self {
        Self {
            boot_flags: 0,
            memory_map: None,
            cpu_info: CpuInfo::new(),
            initialized: false,
        }
    }
}

#[derive(Debug)]
struct CpuInfo {
    features: u64,
    cores: u32,
    architecture: CpuArchitecture,
}

impl CpuInfo {
    const fn new() -> Self {
        Self {
            features: 0,
            cores: 1,
            architecture: CpuArchitecture::Unknown,
        }
    }

    fn detect_features(&mut self) {
        unsafe {
            // CPU feature detection code
            #[cfg(target_arch = "aarch64")]
            {
                asm!(
                    "mrs x0, ID_AA64ISAR0_EL1",
                    out("x0") self.features
                );
            }

            #[cfg(target_arch = "x86_64")]
            {
                asm!(
                    "cpuid",
                    inout("eax") 1 => _,
                    out("ebx") _,
                    out("ecx") self.features,
                    out("edx") _,
                );
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum CpuArchitecture {
    Aarch64,
    X86_64,
    Unknown,
}

// Memory management structures
#[derive(Debug)]
struct MemoryMap {
    regions: &'static [MemoryRegion],
}

#[derive(Debug, Clone, Copy)]
struct MemoryRegion {
    start: u64,
    size: u64,
    region_type: MemoryRegionType,
}

#[derive(Debug, Clone, Copy)]
enum MemoryRegionType {
    Available,
    Reserved,
    Kernel,
    Bootloader,
}

// Early initialization code
fn early_init(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    // Disable interrupts during early initialization
    unsafe { disable_interrupts() };

    // Initialize basic console for debug output
    init_early_console()?;

    // Setup initial memory map
    let mut state = KERNEL_STATE.lock();
    state.memory_map = Some(create_memory_map(boot_info));

    // CPU initialization and feature detection
    state.cpu_info.detect_features();

    // Enable basic memory protection
    setup_memory_protection()?;

    Ok(())
}

#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> ! {
    match early_init(boot_info) {
        Ok(()) => {
            // Continue with rest of kernel initialization
            init_memory_manager();
            init_scheduler();
            init_device_manager();

            // Enable interrupts and jump to scheduler
            unsafe { enable_interrupts() };

            // Mark kernel as initialized
            KERNEL_STATE.lock().initialized = true;

            // Enter main kernel loop
            kernel_loop();
        }
        Err(e) => {
            panic!("Kernel initialization failed: {}", e);
        }
    }
}

fn kernel_loop() -> ! {
    loop {
        // Power management and scheduling
        unsafe {
            #[cfg(target_arch = "aarch64")]
            asm!("wfe"); // Wait for event on ARM

            #[cfg(target_arch = "x86_64")]
            asm!("hlt"); // Halt until next interrupt on x86
        }
    }
}

// Safety functions
unsafe fn disable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    asm!("msr daifset, #2");

    #[cfg(target_arch = "x86_64")]
    asm!("cli");
}

unsafe fn enable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    asm!("msr daifclr, #2");

    #[cfg(target_arch = "x86_64")]
    asm!("sti");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Log panic information to debug console
    if let Some(location) = info.location() {
        println!("Kernel panic at {}:{}", location.file(), location.line());
    }

    // Disable interrupts and halt
    unsafe {
        disable_interrupts();
        loop {
            #[cfg(target_arch = "aarch64")]
            asm!("wfe");

            #[cfg(target_arch = "x86_64")]
            asm!("hlt");
        }
    }
}

// Export symbols needed by the bootloader
#[no_mangle]
pub extern "C" fn _start() -> ! {
    kernel_main(&BootInfo::default())
}

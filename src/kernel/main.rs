#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize essential kernel systems
    init_memory(boot_info);
    init_interrupts();
    init_scheduler();

    loop { /* Kernel main loop */ }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

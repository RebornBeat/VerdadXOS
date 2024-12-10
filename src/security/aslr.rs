// src/security/aslr.rs
use core::sync::atomic::{AtomicU64, Ordering};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedRng};
use spin::Mutex;

// Constants for virtual memory layout
const ASLR_BITS: u64 = 30; // 1GB of randomization space
const USER_STACK_BITS: u64 = 24; // 16MB of stack randomization
const MMAP_BITS: u64 = 28; // 256MB of mmap randomization

#[repr(C)]
pub struct AslrManager {
    rng: Mutex<ChaCha20Rng>,
    entropy_pool: AtomicU64,
    last_base: AtomicU64,
}

impl AslrManager {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
            entropy_pool: AtomicU64::new(0),
            last_base: AtomicU64::new(0),
        }
    }

    pub fn add_entropy(&self, value: u64) {
        self.entropy_pool.fetch_xor(value, Ordering::Relaxed);
    }

    pub fn randomize_base(&self, range: Range<u64>, align: u64) -> u64 {
        let mut rng = self.rng.lock();
        let entropy = self.entropy_pool.load(Ordering::Relaxed);

        // Mix in additional entropy
        rng.set_stream(entropy);

        let range_size = range.end - range.start;
        let aligned_range = range_size / align;
        let random_offset = (rng.next_u64() % aligned_range) * align;

        range.start + random_offset
    }
}

#[derive(Debug)]
pub struct ProcessAslr {
    text_base: u64,
    data_base: u64,
    heap_base: u64,
    mmap_base: u64,
    stack_base: u64,
}

impl ProcessAslr {
    pub fn new(aslr: &AslrManager) -> Self {
        // Generate randomized bases for each segment
        let text_base = aslr.randomize_base(
            Range {
                start: 0x400000,
                end: 0x400000 + (1 << ASLR_BITS),
            },
            4096,
        );

        let data_base = aslr.randomize_base(
            Range {
                start: text_base + (1 << ASLR_BITS),
                end: text_base + (2 << ASLR_BITS),
            },
            4096,
        );

        let heap_base = aslr.randomize_base(
            Range {
                start: data_base + (1 << ASLR_BITS),
                end: data_base + (2 << ASLR_BITS),
            },
            4096,
        );

        Self {
            text_base,
            data_base,
            heap_base,
            mmap_base: 0,
            stack_base: 0,
        }
    }

    pub fn randomize_mmap(&mut self, aslr: &AslrManager, size: u64) -> u64 {
        let base = aslr.randomize_base(
            Range {
                start: self.heap_base + (1 << ASLR_BITS),
                end: self.heap_base + (1 << MMAP_BITS),
            },
            4096,
        );
        self.mmap_base = base;
        base
    }

    pub fn randomize_stack(&mut self, aslr: &AslrManager) -> u64 {
        let base = aslr.randomize_base(
            Range {
                start: 0x7FFF0000_00000000,
                end: 0x7FFFFFFF_FFFF0000,
            },
            4096,
        );
        self.stack_base = base;
        base
    }
}

// Integration with memory management
pub struct AslrPageAllocator {
    inner: PageAllocator,
    aslr: AslrManager,
}

impl AslrPageAllocator {
    pub fn new(page_allocator: PageAllocator, seed: u64) -> Self {
        Self {
            inner: page_allocator,
            aslr: AslrManager::new(seed),
        }
    }

    pub fn allocate_virtual_range(
        &mut self,
        size: usize,
        flags: PageFlags,
    ) -> Result<VirtAddr, MemoryError> {
        let physical = self.inner.allocate_pages(size / PAGE_SIZE, flags)?;

        // Get randomized virtual address
        let virtual_base = self.aslr.randomize_base(
            Range {
                start: 0x1000_0000_0000,
                end: 0x7FFF_FFFF_F000,
            },
            PAGE_SIZE as u64,
        );

        // Map physical to randomized virtual address
        let mut page_tables = self.page_tables.lock();
        page_tables.map_range(VirtAddr::new(virtual_base), physical, size, flags)?;

        Ok(VirtAddr::new(virtual_base))
    }
}

// Kernel initialization
pub fn init_aslr(boot_info: &BootInfo) -> Result<(), InitError> {
    // Get initial entropy from various sources
    let mut initial_entropy = 0u64;

    // CPU timestamp counter
    initial_entropy ^= read_timestamp_counter();

    // Device-specific entropy sources
    #[cfg(target_arch = "aarch64")]
    {
        initial_entropy ^= read_cntvct_el0();
    }

    #[cfg(target_arch = "x86_64")]
    {
        initial_entropy ^= read_rdrand().unwrap_or(0);
    }

    // Initialize ASLR manager
    let aslr = ASLR_MANAGER.get_or_init(|| AslrManager::new(initial_entropy));

    // Set up kernel ASLR regions
    let kernel_aslr = ProcessAslr::new(aslr);
    KERNEL_ASLR.store(kernel_aslr as *const _ as u64, Ordering::SeqCst);

    Ok(())
}

// Hardware-specific entropy sources
#[cfg(target_arch = "x86_64")]
fn read_timestamp_counter() -> u64 {
    unsafe {
        let low: u32;
        let high: u32;
        asm!("rdtsc", out("eax") low, out("edx") high);
        ((high as u64) << 32) | (low as u64)
    }
}

#[cfg(target_arch = "aarch64")]
fn read_cntvct_el0() -> u64 {
    unsafe {
        let value: u64;
        asm!("mrs {}, cntvct_el0", out(reg) value);
        value
    }
}

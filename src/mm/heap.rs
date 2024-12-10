// src/mm/heap.rs
use crate::mm::{MemoryError, MemoryManager, PageFlags};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

#[derive(Debug)]
pub struct SecureHeapAllocator {
    slab_allocator: Mutex<SlabAllocator>,
    large_allocator: Mutex<LargeAllocator>,
    stats: AllocStats,
}

#[derive(Debug)]
struct SlabAllocator {
    slabs: [Slab; SLAB_CLASSES],
    free_slabs: Vec<*mut SlabHeader>,
}

#[derive(Debug)]
struct Slab {
    size_class: usize,
    free_blocks: Vec<*mut BlockHeader>,
    total_blocks: usize,
    used_blocks: usize,
}

#[derive(Debug)]
struct LargeAllocator {
    regions: BTreeMap<usize, LargeRegion>,
    free_list: LinkedList<FreeBlock>,
}

#[repr(C)]
struct SlabHeader {
    magic: u64, // For corruption detection
    size_class: usize,
    free_count: usize,
    first_block: *mut BlockHeader,
    canary: u64, // Stack canary for overflow detection
}

#[repr(C)]
struct BlockHeader {
    magic: u64,
    size: usize,
    next: Option<NonNull<BlockHeader>>,
    canary: u64,
}

unsafe impl GlobalAlloc for SecureHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // Add guard pages for large allocations
        let needs_guard = size >= GUARD_PAGE_THRESHOLD;

        let ptr = if size <= MAX_SLAB_SIZE {
            self.slab_allocator.lock().allocate(size, align)
        } else {
            self.large_allocator
                .lock()
                .allocate(size, align, needs_guard)
        };

        // Initialize memory with pattern for use-after-free detection
        if let Some(ptr) = ptr {
            ptr.as_ptr().write_bytes(ALLOC_PATTERN, size);
        }

        ptr.map_or(core::ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        // Verify memory patterns and canaries
        self.verify_allocation(ptr, layout.size());

        if layout.size() <= MAX_SLAB_SIZE {
            self.slab_allocator.lock().deallocate(ptr, layout.size());
        } else {
            self.large_allocator.lock().deallocate(ptr, layout.size());
        }

        // Poison freed memory
        ptr.write_bytes(DEALLOC_PATTERN, layout.size());
    }
}

impl SlabAllocator {
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let size_class = self.get_size_class(size, align);
        let slab = &mut self.slabs[size_class];

        // Check if we need a new slab
        if slab.free_blocks.is_empty() {
            self.create_new_slab(size_class)?;
        }

        // Get a free block
        let block_ptr = slab.free_blocks.pop()?;
        let block = unsafe { &mut *block_ptr };

        // Verify block integrity
        assert_eq!(block.magic, BLOCK_MAGIC, "Block corruption detected");
        assert_eq!(
            block.canary,
            self.calculate_canary(block_ptr as usize),
            "Block canary mismatch"
        );

        slab.used_blocks += 1;

        // Return pointer to usable memory (after header)
        Some(NonNull::new(unsafe { block_ptr.add(1) as *mut u8 })?)
    }

    fn create_new_slab(&mut self, size_class: usize) -> Option<()> {
        // Allocate a new slab with guard pages
        let layout = Layout::from_size_align(SLAB_SIZE + 2 * PAGE_SIZE, PAGE_SIZE).ok()?;

        let slab_ptr = unsafe {
            let ptr = self.mmap_with_guard_pages(layout)?;
            let header = &mut *(ptr as *mut SlabHeader);

            // Initialize slab header
            header.magic = SLAB_MAGIC;
            header.size_class = size_class;
            header.free_count = 0;
            header.canary = self.calculate_canary(ptr as usize);

            // Split into blocks
            self.initialize_blocks(header, size_class);

            ptr
        };

        self.free_slabs.push(slab_ptr);
        Some(())
    }
}

impl LargeAllocator {
    fn allocate(&mut self, size: usize, align: usize, needs_guard: bool) -> Option<NonNull<u8>> {
        let total_size = if needs_guard {
            size + 2 * PAGE_SIZE
        } else {
            size
        };

        // Try to find a suitable free block
        if let Some(block) = self.find_free_block(total_size, align) {
            return Some(block);
        }

        // Allocate new memory region
        let layout = Layout::from_size_align(total_size, align).ok()?;
        let ptr = unsafe { self.mmap_with_randomization(layout)? };

        // Initialize region tracking
        let region = LargeRegion {
            base: ptr.as_ptr() as usize,
            size: total_size,
            has_guard_pages: needs_guard,
        };
        self.regions.insert(ptr.as_ptr() as usize, region);

        Some(ptr)
    }

    unsafe fn mmap_with_randomization(&self, layout: Layout) -> Option<NonNull<u8>> {
        // Get random offset for ASLR
        let offset = self.get_random_offset(PAGE_SIZE);

        // Map memory with offset
        let ptr = self.mmap(layout.size(), layout.align(), offset)?;

        // Initialize memory protections
        self.protect_region(ptr, layout.size())?;

        Some(NonNull::new(ptr as *mut u8)?)
    }
}

// Constants
const PAGE_SIZE: usize = 4096;
const SLAB_SIZE: usize = 16 * 4096; // 64KB
const MAX_SLAB_SIZE: usize = 4096; // Larger allocations use LargeAllocator
const SLAB_CLASSES: usize = 8; // Power of 2 sizes: 16, 32, 64, 128, 256, 512, 1024, 2048
const GUARD_PAGE_THRESHOLD: usize = 1024 * 1024; // 1MB
const BLOCK_MAGIC: u64 = 0xDEADBEEFCAFEBABE;
const SLAB_MAGIC: u64 = 0xB16B00B5DEADC0DE;
const ALLOC_PATTERN: u8 = 0xAA;
const DEALLOC_PATTERN: u8 = 0xDD;

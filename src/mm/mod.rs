// src/mm/mod.rs
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub mod allocator;
pub mod cache;
pub mod page_table;

// Memory constants
const PAGE_SIZE: usize = 4096;
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
const KERNEL_HEAP_START: usize = 0xFFFF800000000000;
const KERNEL_HEAP_SIZE: usize = 1024 * 1024 * 1024; // 1GB initial heap

#[repr(C)]
pub struct MemoryManager {
    page_allocator: Mutex<PageAllocator>,
    kernel_heap: Mutex<KernelHeap>,
    page_tables: Mutex<PageTableManager>,
    physical_memory_size: AtomicU64,
}

impl MemoryManager {
    pub fn init(&self, boot_info: &BootInfo) -> Result<(), MemoryError> {
        // Initialize physical page allocator
        let mut allocator = self.page_allocator.lock();
        allocator.init(boot_info.memory_map())?;

        // Setup kernel heap
        let mut heap = self.kernel_heap.lock();
        heap.init(KERNEL_HEAP_START, KERNEL_HEAP_SIZE)?;

        // Initialize page tables
        let mut tables = self.page_tables.lock();
        tables.init()?;

        Ok(())
    }

    pub fn allocate_pages(&self, count: usize, flags: PageFlags) -> Result<PhysAddr, MemoryError> {
        let mut allocator = self.page_allocator.lock();
        allocator.allocate_contiguous(count, flags)
    }

    pub fn map_memory(
        &self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MemoryError> {
        let mut tables = self.page_tables.lock();
        tables.map(virt, phys, flags)
    }
}

#[repr(C)]
pub struct PageAllocator {
    free_lists: [List<Frame>; MAX_ORDER],
    used_frames: BitMap,
}

impl PageAllocator {
    pub fn allocate_contiguous(
        &mut self,
        count: usize,
        flags: PageFlags,
    ) -> Result<PhysAddr, MemoryError> {
        let order = self.required_order(count);

        // Try to find a block of the required size
        if let Some(frame) = self.free_lists[order].pop() {
            self.used_frames.set(frame.index(), true);
            return Ok(frame.start_address());
        }

        // If no block found, try splitting a larger block
        for higher_order in (order + 1)..MAX_ORDER {
            if let Some(frame) = self.free_lists[higher_order].pop() {
                self.split_block(frame, higher_order, order)?;
                let allocated = self.free_lists[order]
                    .pop()
                    .ok_or(MemoryError::AllocationFailed)?;
                self.used_frames.set(allocated.index(), true);
                return Ok(allocated.start_address());
            }
        }

        Err(MemoryError::OutOfMemory)
    }

    fn split_block(
        &mut self,
        frame: Frame,
        from_order: usize,
        to_order: usize,
    ) -> Result<(), MemoryError> {
        let mut current_frame = frame;
        let mut current_order = from_order;

        while current_order > to_order {
            let (left, right) = self.split_frame(current_frame, current_order)?;
            self.free_lists[current_order - 1].push(right);
            current_frame = left;
            current_order -= 1;
        }

        self.free_lists[to_order].push(current_frame);
        Ok(())
    }
}

#[derive(Debug)]
pub enum MemoryError {
    OutOfMemory,
    InvalidAddress,
    AllocationFailed,
    MappingFailed,
    PermissionDenied,
}

// Page table management
#[repr(C)]
pub struct PageTableManager {
    root_table: PhysAddr,
    table_allocator: Mutex<TableAllocator>,
}

impl PageTableManager {
    pub fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MemoryError> {
        let mut table = self.get_or_create_table(virt)?;
        table.map_page(virt, phys, flags)
    }

    pub fn protect_range(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), MemoryError> {
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end - 1u64);

        for page in Page::range_inclusive(start_page, end_page) {
            self.update_flags(page.start_address(), flags)?;
        }

        // Flush TLB for the affected range
        self.flush_tlb_range(start, end);
        Ok(())
    }
}

bitflags::bitflags! {
    pub struct PageFlags: u64 {
        const PRESENT = 1 << 0;
        const WRITABLE = 1 << 1;
        const USER = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE = 1 << 4;
        const ACCESSED = 1 << 5;
        const DIRTY = 1 << 6;
        const HUGE = 1 << 7;
        const GLOBAL = 1 << 8;
        const NO_EXECUTE = 1 << 63;
    }
}

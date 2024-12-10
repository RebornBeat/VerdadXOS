// src/process/isolation.rs
use crate::mm::{MemoryError, MemoryManager, PageFlags};
use crate::security::aslr::AslrManager;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug)]
pub struct ProcessMemorySpace {
    cr3: PhysAddr, // Page table base register
    memory_regions: Vec<MemoryRegion>,
    aslr_state: ProcessAslr,
    permissions: ProcessPermissions,
}

#[derive(Debug)]
struct MemoryRegion {
    start: VirtAddr,
    size: usize,
    flags: PageFlags,
    region_type: RegionType,
}

#[derive(Debug, Clone, Copy)]
enum RegionType {
    Text,
    Data,
    Stack,
    Heap,
    SharedMemory,
    Vdso, // Virtual dynamic shared object
}

#[derive(Debug)]
pub struct ProcessIsolator {
    memory_manager: &'static MemoryManager,
    aslr_manager: &'static AslrManager,
    active_processes: Mutex<Vec<ProcessId>>,
}

impl ProcessIsolator {
    pub fn new(memory_manager: &'static MemoryManager, aslr_manager: &'static AslrManager) -> Self {
        Self {
            memory_manager,
            aslr_manager,
            active_processes: Mutex::new(Vec::new()),
        }
    }

    pub fn create_process_space(&self) -> Result<ProcessMemorySpace, MemoryError> {
        // Allocate new page table structure
        let cr3 = self.memory_manager.allocate_page_table()?;

        // Initialize ASLR for the new process
        let aslr_state = self.aslr_manager.create_process_aslr();

        // Create basic memory layout
        let mut space = ProcessMemorySpace {
            cr3,
            memory_regions: Vec::new(),
            aslr_state,
            permissions: ProcessPermissions::default(),
        };

        // Set up initial memory regions
        self.setup_initial_regions(&mut space)?;

        Ok(space)
    }

    fn setup_initial_regions(&self, space: &mut ProcessMemorySpace) -> Result<(), MemoryError> {
        // Stack region (with guard pages)
        let stack_base = space.aslr_state.randomize_stack();
        self.create_protected_region(
            space,
            stack_base,
            STACK_SIZE,
            PageFlags::USER | PageFlags::WRITABLE,
            RegionType::Stack,
            true, // Add guard pages
        )?;

        // Initial heap region
        let heap_base = space.aslr_state.randomize_heap();
        self.create_protected_region(
            space,
            heap_base,
            INITIAL_HEAP_SIZE,
            PageFlags::USER | PageFlags::WRITABLE,
            RegionType::Heap,
            false,
        )?;

        // VDSO region (read-only shared code)
        let vdso_base = space.aslr_state.randomize_vdso();
        self.map_vdso(space, vdso_base)?;

        Ok(())
    }

    pub fn switch_to_process(&self, process: &ProcessMemorySpace) {
        unsafe {
            // Save current FPU state if needed
            self.save_fpu_state();

            // Switch to new page table
            self.switch_page_table(process.cr3);

            // Update CPU segregation registers
            self.update_segment_registers(process);

            // Clear TLB for security
            self.flush_tlb_full();
        }
    }

    pub fn handle_page_fault(
        &self,
        fault_addr: VirtAddr,
        error_code: u64,
    ) -> Result<(), MemoryError> {
        let current_process = self.get_current_process()?;

        // Check if address is within process space
        if !self.is_valid_process_address(current_process, fault_addr) {
            return Err(MemoryError::InvalidAccess);
        }

        match self.get_fault_type(error_code) {
            FaultType::MissingPage => self.handle_missing_page(current_process, fault_addr),
            FaultType::ProtectionViolation => {
                self.handle_protection_violation(current_process, fault_addr, error_code)
            }
            FaultType::ExecuteViolation => {
                // NX violation - always fail for security
                Err(MemoryError::ExecuteViolation)
            }
        }
    }

    fn handle_missing_page(
        &self,
        process: &ProcessMemorySpace,
        addr: VirtAddr,
    ) -> Result<(), MemoryError> {
        // Find the region containing this address
        let region = process
            .memory_regions
            .iter()
            .find(|r| r.contains(addr))
            .ok_or(MemoryError::InvalidAccess)?;

        match region.region_type {
            RegionType::Stack => self.expand_stack(process, addr),
            RegionType::Heap => self.expand_heap(process, addr),
            _ => Err(MemoryError::InvalidAccess),
        }
    }

    fn create_protected_region(
        &self,
        space: &mut ProcessMemorySpace,
        base: VirtAddr,
        size: usize,
        flags: PageFlags,
        region_type: RegionType,
        add_guard_pages: bool,
    ) -> Result<(), MemoryError> {
        // Add guard pages if requested
        let total_size = if add_guard_pages {
            size + 2 * PAGE_SIZE
        } else {
            size
        };

        // Allocate physical memory
        let phys_mem = self.memory_manager.allocate_pages(total_size / PAGE_SIZE)?;

        // Set up mapping with guard pages if needed
        if add_guard_pages {
            // Map lower guard page as non-accessible
            self.memory_manager
                .map_page(base, phys_mem, PageFlags::empty())?;

            // Map main region
            self.memory_manager
                .map_range(base + PAGE_SIZE, phys_mem + PAGE_SIZE, size, flags)?;

            // Map upper guard page as non-accessible
            self.memory_manager.map_page(
                base + size + PAGE_SIZE,
                phys_mem + size + PAGE_SIZE,
                PageFlags::empty(),
            )?;
        } else {
            // Map region without guard pages
            self.memory_manager.map_range(base, phys_mem, size, flags)?;
        }

        // Record the memory region
        space.memory_regions.push(MemoryRegion {
            start: base,
            size: total_size,
            flags,
            region_type,
        });

        Ok(())
    }

    fn map_vdso(&self, space: &mut ProcessMemorySpace, base: VirtAddr) -> Result<(), MemoryError> {
        // Map the VDSO pages as read-only executable
        self.memory_manager.map_range(
            base,
            VDSO_PHYSICAL_BASE,
            VDSO_SIZE,
            PageFlags::USER | PageFlags::PRESENT,
        )?;

        space.memory_regions.push(MemoryRegion {
            start: base,
            size: VDSO_SIZE,
            flags: PageFlags::USER | PageFlags::PRESENT,
            region_type: RegionType::Vdso,
        });

        Ok(())
    }
}

// Constants
const PAGE_SIZE: usize = 4096;
const STACK_SIZE: usize = 8 * 1024 * 1024; // 8MB
const INITIAL_HEAP_SIZE: usize = 4 * 1024 * 1024; // 4MB
const VDSO_SIZE: usize = 4096;
const VDSO_PHYSICAL_BASE: PhysAddr = PhysAddr::new(0xFFFF_FF80_0000_0000);

#[repr(u64)]
enum FaultType {
    MissingPage = 0,
    ProtectionViolation = 1,
    ExecuteViolation = 2,
}

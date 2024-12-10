// src/mm/cow.rs
use crate::mm::{MemoryError, MemoryManager, PageFlags};
use crate::process::ProcessMemorySpace;
use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Debug)]
pub struct CowManager {
    memory_manager: &'static MemoryManager,
    page_refs: Mutex<BTreeMap<PhysAddr, PageReference>>,
}

#[derive(Debug)]
struct PageReference {
    count: usize,
    flags: PageFlags,
    dirty: bool,
    source: ProcessId,
}

#[derive(Debug)]
pub struct CowRegion {
    base_addr: VirtAddr,
    size: usize,
    original_flags: PageFlags,
    pages: Vec<CowPage>,
}

#[derive(Debug)]
struct CowPage {
    phys_addr: PhysAddr,
    flags: PageFlags,
    state: CowState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CowState {
    Shared,
    Private,
    Unmodified,
}

impl CowManager {
    pub fn new(memory_manager: &'static MemoryManager) -> Self {
        Self {
            memory_manager,
            page_refs: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn fork_process(
        &self,
        parent: &ProcessMemorySpace,
        child: &mut ProcessMemorySpace,
    ) -> Result<(), CowError> {
        // Clone parent's page tables with CoW mappings
        for region in parent.memory_regions() {
            if region.is_cow_eligible() {
                self.setup_cow_region(parent, child, region)?;
            } else {
                // Direct copy for non-CoW regions (e.g., read-only sections)
                self.copy_region(parent, child, region)?;
            }
        }

        Ok(())
    }

    fn setup_cow_region(
        &self,
        parent: &ProcessMemorySpace,
        child: &mut ProcessMemorySpace,
        region: &MemoryRegion,
    ) -> Result<(), CowError> {
        let mut page_refs = self.page_refs.lock();

        for page in region.pages() {
            let phys_addr = parent.get_physical_address(page.virt_addr)?;

            // Make the page read-only in both parent and child
            let cow_flags = page.flags.remove(PageFlags::WRITABLE) | PageFlags::COW;

            // Update parent's page table
            self.memory_manager.update_page_flags(
                parent.page_table(),
                page.virt_addr,
                cow_flags,
            )?;

            // Map the page in child's address space
            self.memory_manager.map_page(
                child.page_table(),
                page.virt_addr,
                phys_addr,
                cow_flags,
            )?;

            // Track reference count
            page_refs
                .entry(phys_addr)
                .and_modify(|ref_count| ref_count.count += 1)
                .or_insert(PageReference {
                    count: 2, // Parent and child
                    flags: page.flags,
                    dirty: false,
                    source: parent.id(),
                });
        }

        Ok(())
    }

    pub fn handle_cow_fault(
        &self,
        process: &mut ProcessMemorySpace,
        fault_addr: VirtAddr,
    ) -> Result<(), CowError> {
        let mut page_refs = self.page_refs.lock();

        // Get the physical address of the faulting page
        let old_phys_addr = process.get_physical_address(fault_addr)?;

        let page_ref = page_refs
            .get_mut(&old_phys_addr)
            .ok_or(CowError::InvalidPage)?;

        if page_ref.count == 1 {
            // Last reference - just make it writable again
            let writable_flags = page_ref.flags | PageFlags::WRITABLE;
            self.memory_manager.update_page_flags(
                process.page_table(),
                fault_addr,
                writable_flags,
            )?;

            page_refs.remove(&old_phys_addr);
        } else {
            // Create a new private copy
            let new_page = self.memory_manager.allocate_page()?;

            // Copy the page content
            self.copy_page_contents(old_phys_addr, new_page)?;

            // Map the new page as writable
            self.memory_manager.map_page(
                process.page_table(),
                fault_addr,
                new_page,
                page_ref.flags | PageFlags::WRITABLE,
            )?;

            // Update reference count
            page_ref.count -= 1;
        }

        Ok(())
    }

    fn copy_page_contents(&self, src: PhysAddr, dst: PhysAddr) -> Result<(), CowError> {
        // Temporarily map both pages into kernel space
        let src_virt = self.memory_manager.temp_map_page(src)?;
        let dst_virt = self.memory_manager.temp_map_page(dst)?;

        // Perform the copy
        unsafe {
            core::ptr::copy_nonoverlapping(src_virt.as_ptr(), dst_virt.as_mut_ptr(), PAGE_SIZE);
        }

        // Unmap temporary mappings
        self.memory_manager.temp_unmap_page(src_virt)?;
        self.memory_manager.temp_unmap_page(dst_virt)?;

        Ok(())
    }

    pub fn optimize_cow_pages(&self, process: &mut ProcessMemorySpace) -> Result<(), CowError> {
        let mut page_refs = self.page_refs.lock();

        // Look for opportunities to merge identical pages
        let mut page_contents = BTreeMap::new();

        for region in process.memory_regions() {
            if !region.flags.contains(PageFlags::COW) {
                continue;
            }

            for page in region.pages() {
                let phys_addr = process.get_physical_address(page.virt_addr)?;
                let hash = self.hash_page_contents(phys_addr)?;

                if let Some(&existing_addr) = page_contents.get(&hash) {
                    // Found identical page - merge them
                    self.merge_identical_pages(
                        process,
                        page.virt_addr,
                        phys_addr,
                        existing_addr,
                        &mut page_refs,
                    )?;
                } else {
                    page_contents.insert(hash, phys_addr);
                }
            }
        }

        Ok(())
    }

    fn merge_identical_pages(
        &self,
        process: &mut ProcessMemorySpace,
        virt_addr: VirtAddr,
        old_phys: PhysAddr,
        new_phys: PhysAddr,
        page_refs: &mut BTreeMap<PhysAddr, PageReference>,
    ) -> Result<(), CowError> {
        // Update mapping to point to existing page
        self.memory_manager.map_page(
            process.page_table(),
            virt_addr,
            new_phys,
            PageFlags::COW | PageFlags::PRESENT,
        )?;

        // Update reference counts
        if let Some(ref_count) = page_refs.get_mut(&new_phys) {
            ref_count.count += 1;
        }

        if let Some(ref_count) = page_refs.get_mut(&old_phys) {
            ref_count.count -= 1;
            if ref_count.count == 0 {
                // Free the old page
                self.memory_manager.free_page(old_phys)?;
                page_refs.remove(&old_phys);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum CowError {
    InvalidPage,
    MemoryError(MemoryError),
    InvalidAddress,
    PermissionDenied,
}

// Constants
const PAGE_SIZE: usize = 4096;

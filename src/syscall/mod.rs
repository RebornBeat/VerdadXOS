// src/syscall/mod.rs
use crate::mm::{MemoryError, MemoryManager, PageFlags};
use crate::security::aslr::AslrManager;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct SyscallHandler {
    memory_manager: &'static MemoryManager,
    aslr_manager: &'static AslrManager,
    syscall_count: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum SyscallNumber {
    Mmap = 0,
    Munmap = 1,
    Mprotect = 2,
    Brk = 3,
    Exit = 60,
}

#[repr(C)]
pub struct MmapArgs {
    addr: u64,
    length: usize,
    prot: u32,
    flags: u32,
    fd: i32,
    offset: u64,
}

impl SyscallHandler {
    pub fn handle_syscall(&self, number: u64, args: &[u64; 6]) -> Result<u64, SyscallError> {
        self.syscall_count.fetch_add(1, Ordering::Relaxed);

        match number {
            n if n == SyscallNumber::Mmap as u64 => self.sys_mmap(args),
            n if n == SyscallNumber::Munmap as u64 => self.sys_munmap(args),
            n if n == SyscallNumber::Mprotect as u64 => self.sys_mprotect(args),
            n if n == SyscallNumber::Brk as u64 => self.sys_brk(args),
            _ => Err(SyscallError::InvalidSyscall),
        }
    }

    fn sys_mmap(&self, args: &[u64; 6]) -> Result<u64, SyscallError> {
        let mmap_args = unsafe { &*(args.as_ptr() as *const MmapArgs) };

        // Validate arguments
        if mmap_args.length == 0 || mmap_args.length > MAX_MMAP_SIZE {
            return Err(SyscallError::InvalidArgument);
        }

        // Convert protection flags
        let page_flags = self.prot_to_page_flags(mmap_args.prot)?;

        // Handle MAP_FIXED specially - requires extra security checks
        if mmap_args.flags & MAP_FIXED != 0 {
            self.handle_fixed_mapping(mmap_args, page_flags)?;
        }

        // Get randomized address from ASLR if no specific address requested
        let addr = if mmap_args.addr == 0 {
            self.aslr_manager.randomize_mmap(mmap_args.length as u64)
        } else {
            self.validate_address_range(mmap_args.addr, mmap_args.length)?
        };

        // Perform the mapping
        match self.memory_manager.map_region(
            addr,
            mmap_args.length,
            page_flags,
            mmap_args.fd,
            mmap_args.offset,
        ) {
            Ok(mapped_addr) => Ok(mapped_addr),
            Err(e) => Err(SyscallError::MemoryError(e)),
        }
    }

    fn sys_munmap(&self, args: &[u64; 6]) -> Result<u64, SyscallError> {
        let addr = args[0];
        let length = args[1] as usize;

        // Validate arguments
        if !self.is_aligned(addr) || length == 0 {
            return Err(SyscallError::InvalidArgument);
        }

        // Check address range
        self.validate_address_range(addr, length)?;

        // Perform unmapping
        match self.memory_manager.unmap_region(addr, length) {
            Ok(()) => Ok(0),
            Err(e) => Err(SyscallError::MemoryError(e)),
        }
    }

    fn sys_mprotect(&self, args: &[u64; 6]) -> Result<u64, SyscallError> {
        let addr = args[0];
        let length = args[1] as usize;
        let prot = args[2] as u32;

        // Validate arguments
        if !self.is_aligned(addr) || length == 0 {
            return Err(SyscallError::InvalidArgument);
        }

        // Convert protection flags
        let page_flags = self.prot_to_page_flags(prot)?;

        // Validate address range
        self.validate_address_range(addr, length)?;

        // Update page protection
        match self.memory_manager.protect_region(addr, length, page_flags) {
            Ok(()) => Ok(0),
            Err(e) => Err(SyscallError::MemoryError(e)),
        }
    }

    fn sys_brk(&self, args: &[u64; 6]) -> Result<u64, SyscallError> {
        let new_brk = args[0];

        // If new_brk is 0, return current break
        if new_brk == 0 {
            return Ok(self.memory_manager.get_current_break());
        }

        // Validate new break address
        self.validate_brk_address(new_brk)?;

        // Attempt to set new break
        match self.memory_manager.set_program_break(new_brk) {
            Ok(new_break) => Ok(new_break),
            Err(e) => Err(SyscallError::MemoryError(e)),
        }
    }

    // Helper functions
    fn prot_to_page_flags(&self, prot: u32) -> Result<PageFlags, SyscallError> {
        let mut flags = PageFlags::PRESENT;

        if prot & PROT_WRITE != 0 {
            flags |= PageFlags::WRITABLE;
        }
        if prot & PROT_EXEC == 0 {
            flags |= PageFlags::NO_EXECUTE;
        }
        if prot & PROT_USER != 0 {
            flags |= PageFlags::USER;
        }

        Ok(flags)
    }

    fn validate_address_range(&self, addr: u64, length: usize) -> Result<u64, SyscallError> {
        if !self.is_aligned(addr) {
            return Err(SyscallError::InvalidAlignment);
        }

        let end_addr = addr
            .checked_add(length as u64)
            .ok_or(SyscallError::InvalidAddress)?;

        // Check against process address space limits
        if addr < PROCESS_MIN_ADDR || end_addr > PROCESS_MAX_ADDR {
            return Err(SyscallError::InvalidAddress);
        }

        // Ensure range doesn't overlap with kernel space
        if addr >= KERNEL_BASE || end_addr > KERNEL_BASE {
            return Err(SyscallError::PermissionDenied);
        }

        Ok(addr)
    }

    fn handle_fixed_mapping(&self, args: &MmapArgs, flags: PageFlags) -> Result<(), SyscallError> {
        // Additional security checks for fixed mappings
        if args.addr < PAGE_SIZE {
            return Err(SyscallError::InvalidAddress);
        }

        // Check for sensitive regions
        if self.is_sensitive_region(args.addr, args.length) {
            return Err(SyscallError::PermissionDenied);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum SyscallError {
    InvalidSyscall,
    InvalidArgument,
    InvalidAddress,
    InvalidAlignment,
    PermissionDenied,
    MemoryError(MemoryError),
}

// Constants
const PAGE_SIZE: usize = 4096;
const MAX_MMAP_SIZE: usize = 1 << 30; // 1GB
const PROCESS_MIN_ADDR: u64 = 0x1000;
const PROCESS_MAX_ADDR: u64 = 0x7FFF_FFFF_F000;
const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;

// Protection flags
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;
const PROT_USER: u32 = 0x8;

// Mapping flags
const MAP_SHARED: u32 = 0x1;
const MAP_PRIVATE: u32 = 0x2;
const MAP_FIXED: u32 = 0x10;

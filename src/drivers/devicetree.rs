// src/drivers/devicetree.rs
use crate::mm::{MemoryError, MemoryManager};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug)]
pub struct HardwareManager {
    acpi_parser: AcpiParser,
    dt_parser: DeviceTreeParser,
    device_map: Mutex<BTreeMap<DeviceId, DeviceNode>>,
}

#[derive(Debug)]
struct DeviceTreeParser {
    dt_base: PhysAddr,
    string_block: *const u8,
    struct_block: *const u8,
    memory_reservations: Vec<MemoryReservation>,
}

#[derive(Debug)]
struct AcpiParser {
    rsdp: Option<&'static RSDP>,
    rsdt: Option<&'static RSDT>,
    xsdt: Option<&'static XSDT>,
    tables: BTreeMap<TableSignature, AcpiTable>,
}

#[derive(Debug)]
struct DeviceNode {
    name: &'static str,
    compatible: Vec<&'static str>,
    reg: Vec<RegProperty>,
    interrupts: Vec<Interrupt>,
    children: Vec<DeviceId>,
    properties: BTreeMap<&'static str, PropertyValue>,
}

#[repr(C, packed)]
struct DeviceTreeHeader {
    magic: u32,
    total_size: u32,
    off_struct: u32,
    off_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid: u32,
    size_strings: u32,
    size_struct: u32,
}

impl HardwareManager {
    pub fn new() -> Self {
        Self {
            acpi_parser: AcpiParser::new(),
            dt_parser: DeviceTreeParser::new(),
            device_map: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn detect_platform(&mut self) -> Result<Platform, HardwareError> {
        // Try ACPI first (typically x86)
        if let Ok(rsdp) = self.find_rsdp() {
            self.acpi_parser.init(rsdp)?;
            Ok(Platform::Acpi)
        }
        // Fall back to Device Tree (typically ARM)
        else if let Ok(dt_addr) = self.find_device_tree() {
            self.dt_parser.init(dt_addr)?;
            Ok(Platform::DeviceTree)
        } else {
            Err(HardwareError::NoPlatformDetected)
        }
    }

    pub fn enumerate_devices(&mut self) -> Result<Vec<DeviceId>, HardwareError> {
        match self.detect_platform()? {
            Platform::Acpi => self.enumerate_acpi_devices(),
            Platform::DeviceTree => self.enumerate_dt_devices(),
        }
    }
}

impl DeviceTreeParser {
    pub fn init(&mut self, dt_addr: PhysAddr) -> Result<(), HardwareError> {
        // Validate Device Tree blob
        let header = unsafe { &*(dt_addr.as_ptr() as *const DeviceTreeHeader) };
        if header.magic != FDT_MAGIC {
            return Err(HardwareError::InvalidDeviceTree);
        }

        // Set up basic pointers
        self.dt_base = dt_addr;
        self.string_block = unsafe { dt_addr.as_ptr().add(header.off_strings as usize) };
        self.struct_block = unsafe { dt_addr.as_ptr().add(header.off_struct as usize) };

        // Parse memory reservations
        self.parse_memory_reservations(header)?;

        Ok(())
    }

    fn parse_node(&mut self, ptr: *const u8) -> Result<(DeviceNode, *const u8), HardwareError> {
        let mut current_ptr = ptr;
        let mut node = DeviceNode::new();

        // Parse node name
        let name_len = self.read_string_length(current_ptr);
        node.name = self.read_string(current_ptr, name_len)?;
        current_ptr = unsafe { current_ptr.add(name_len) };

        // Parse properties
        while !self.is_end_node(current_ptr) {
            let token = self.read_token(current_ptr);
            match token {
                FDT_PROP => {
                    let (prop, next_ptr) = self.parse_property(current_ptr)?;
                    node.add_property(prop);
                    current_ptr = next_ptr;
                }
                FDT_BEGIN_NODE => {
                    let (child, next_ptr) = self.parse_node(current_ptr)?;
                    node.children.push(DeviceId::new());
                    current_ptr = next_ptr;
                }
                _ => return Err(HardwareError::InvalidDeviceTree),
            }
        }

        Ok((node, unsafe { current_ptr.add(FDT_TOKEN_SIZE) }))
    }

    fn parse_property(&self, ptr: *const u8) -> Result<(Property, *const u8), HardwareError> {
        let len = self.read_u32(ptr);
        let nameoff = self.read_u32(unsafe { ptr.add(4) });
        let data = unsafe { ptr.add(8) };
        let name = self.get_string(nameoff)?;

        let property = match name {
            "compatible" => self.parse_compatible(data, len)?,
            "reg" => self.parse_reg(data, len)?,
            "interrupts" => self.parse_interrupts(data, len)?,
            _ => self.parse_generic(data, len)?,
        };

        Ok((property, unsafe { data.add(len as usize) }))
    }
}

impl AcpiParser {
    pub fn init(&mut self, rsdp: &'static RSDP) -> Result<(), HardwareError> {
        self.rsdp = Some(rsdp);

        // Validate RSDP
        if !self.validate_rsdp(rsdp) {
            return Err(HardwareError::InvalidAcpiTable);
        }

        // Parse RSDT/XSDT
        if rsdp.revision >= 2 {
            self.parse_xsdt(rsdp.xsdt_address)?;
        } else {
            self.parse_rsdt(rsdp.rsdt_address)?;
        }

        Ok(())
    }

    fn parse_xsdt(&mut self, addr: u64) -> Result<(), HardwareError> {
        let xsdt = unsafe { &*(addr as *const XSDT) };

        // Validate XSDT
        if !self.validate_table_header(&xsdt.header) {
            return Err(HardwareError::InvalidAcpiTable);
        }

        // Parse all tables
        let entries = xsdt.entries();
        for entry in entries {
            self.parse_table(entry)?;
        }

        Ok(())
    }

    fn parse_table(&mut self, addr: u64) -> Result<(), HardwareError> {
        let header = unsafe { &*(addr as *const AcpiTableHeader) };

        // Validate table
        if !self.validate_table_header(header) {
            return Err(HardwareError::InvalidAcpiTable);
        }

        // Parse based on signature
        match header.signature {
            MADT_SIGNATURE => self.parse_madt(addr)?,
            FADT_SIGNATURE => self.parse_fadt(addr)?,
            MCFG_SIGNATURE => self.parse_mcfg(addr)?,
            _ => (),
        }

        Ok(())
    }
}

// Constants
const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;
const FDT_TOKEN_SIZE: usize = 4;

const RSDP_SIGNATURE: &[u8] = b"RSD PTR ";
const MADT_SIGNATURE: u32 = u32::from_le_bytes(*b"APIC");
const FADT_SIGNATURE: u32 = u32::from_le_bytes(*b"FACP");
const MCFG_SIGNATURE: u32 = u32::from_le_bytes(*b"MCFG");

#[derive(Debug)]
pub enum HardwareError {
    InvalidDeviceTree,
    InvalidAcpiTable,
    NoPlatformDetected,
    ParseError,
    MemoryError(MemoryError),
}

// src/drivers/block/mod.rs
use crate::mm::{MemoryManager, PageFlags};
use crate::sync::Mutex;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::cmp::min;

pub struct BlockDeviceManager {
    devices: Mutex<BTreeMap<DeviceId, BlockDevice>>,
    request_queue: Mutex<VecDeque<BlockRequest>>,
    cache: Mutex<BlockCache>,
}

pub struct BlockDevice {
    info: BlockDeviceInfo,
    driver: Box<dyn BlockDriver>,
    state: BlockDeviceState,
    queue: VecDeque<BlockRequest>,
}

#[derive(Debug, Clone)]
pub struct BlockDeviceInfo {
    sector_size: usize,
    total_sectors: u64,
    max_transfer: usize,
    capabilities: BlockDeviceCapabilities,
}

#[derive(Debug)]
pub struct BlockRequest {
    device_id: DeviceId,
    operation: BlockOperation,
    sector: u64,
    num_sectors: u32,
    buffer: *mut u8,
    callback: Option<BlockCallback>,
}

#[derive(Debug, Clone, Copy)]
pub enum BlockOperation {
    Read,
    Write,
    Flush,
    Trim,
}

pub trait BlockDriver: Send + Sync {
    fn init(&mut self) -> Result<BlockDeviceInfo, BlockDriverError>;
    fn read_sectors(
        &mut self,
        sector: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockDriverError>;
    fn write_sectors(
        &mut self,
        sector: u64,
        count: u32,
        buffer: &[u8],
    ) -> Result<(), BlockDriverError>;
    fn flush(&mut self) -> Result<(), BlockDriverError>;
    fn trim(&mut self, sector: u64, count: u32) -> Result<(), BlockDriverError>;
}

impl BlockDeviceManager {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(BTreeMap::new()),
            request_queue: Mutex::new(VecDeque::new()),
            cache: Mutex::new(BlockCache::new()),
        }
    }

    pub fn register_device(
        &self,
        device_id: DeviceId,
        driver: Box<dyn BlockDriver>,
    ) -> Result<(), BlockDriverError> {
        let mut devices = self.devices.lock();

        // Initialize the driver
        let mut driver = driver;
        let info = driver.init()?;

        // Create new block device
        let device = BlockDevice {
            info,
            driver,
            state: BlockDeviceState::Ready,
            queue: VecDeque::new(),
        };

        // Add to device map
        devices.insert(device_id, device);

        Ok(())
    }

    pub fn submit_request(&self, request: BlockRequest) -> Result<(), BlockDriverError> {
        let mut devices = self.devices.lock();

        // Validate request
        self.validate_request(&request)?;

        // Get target device
        let device = devices
            .get_mut(&request.device_id)
            .ok_or(BlockDriverError::DeviceNotFound)?;

        // Check if request can be served from cache
        if let Some(data) = self.check_cache(&request)? {
            // Handle cached data
            self.complete_request(request, data)?;
            return Ok(());
        }

        // Add to device queue
        device.queue.push_back(request);

        // Process queue if device is ready
        if device.state == BlockDeviceState::Ready {
            self.process_device_queue(device)?;
        }

        Ok(())
    }

    fn process_device_queue(&self, device: &mut BlockDevice) -> Result<(), BlockDriverError> {
        while let Some(request) = device.queue.pop_front() {
            match request.operation {
                BlockOperation::Read => {
                    let mut buffer = unsafe {
                        core::slice::from_raw_parts_mut(
                            request.buffer,
                            request.num_sectors as usize * device.info.sector_size,
                        )
                    };

                    device
                        .driver
                        .read_sectors(request.sector, request.num_sectors, buffer)?;

                    // Update cache
                    self.cache
                        .lock()
                        .add_sectors(request.device_id, request.sector, buffer)?;
                }
                BlockOperation::Write => {
                    let buffer = unsafe {
                        core::slice::from_raw_parts(
                            request.buffer,
                            request.num_sectors as usize * device.info.sector_size,
                        )
                    };

                    device
                        .driver
                        .write_sectors(request.sector, request.num_sectors, buffer)?;

                    // Invalidate cache
                    self.cache.lock().invalidate_sectors(
                        request.device_id,
                        request.sector,
                        request.num_sectors,
                    )?;
                }
                BlockOperation::Flush => {
                    device.driver.flush()?;
                }
                BlockOperation::Trim => {
                    device.driver.trim(request.sector, request.num_sectors)?;
                }
            }

            // Call completion callback if provided
            if let Some(callback) = request.callback {
                callback(Ok(()));
            }
        }

        Ok(())
    }

    fn validate_request(&self, request: &BlockRequest) -> Result<(), BlockDriverError> {
        let devices = self.devices.lock();
        let device = devices
            .get(&request.device_id)
            .ok_or(BlockDriverError::DeviceNotFound)?;

        // Check sector bounds
        if request.sector + request.num_sectors as u64 > device.info.total_sectors {
            return Err(BlockDriverError::InvalidSector);
        }

        // Check transfer size
        if (request.num_sectors as usize * device.info.sector_size) > device.info.max_transfer {
            return Err(BlockDriverError::InvalidTransferSize);
        }

        Ok(())
    }
}

#[derive(Debug)]
struct BlockCache {
    entries: BTreeMap<CacheKey, CacheEntry>,
    size: usize,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CacheKey {
    device_id: DeviceId,
    sector: u64,
}

#[derive(Debug)]
struct CacheEntry {
    data: Vec<u8>,
    timestamp: u64,
    dirty: bool,
}

#[derive(Debug, PartialEq)]
enum BlockDeviceState {
    Ready,
    Busy,
    Error,
}

#[derive(Debug)]
pub enum BlockDriverError {
    DeviceNotFound,
    InvalidSector,
    InvalidTransferSize,
    IoError,
    DeviceBusy,
    WriteProtected,
    HardwareError,
    CacheError,
}

type BlockCallback = fn(Result<(), BlockDriverError>) -> ();

// Constants
const CACHE_SIZE: usize = 4 * 1024 * 1024; // 4MB cache
const MAX_TRANSFER_SIZE: usize = 128 * 1024; // 128KB per transfer
const MAX_QUEUED_REQUESTS: usize = 256;

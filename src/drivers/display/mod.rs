// src/drivers/display/mod.rs
use crate::mm::{MemoryManager, PageFlags};
use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct DisplayManager {
    devices: Mutex<BTreeMap<DeviceId, DisplayDevice>>,
    active_display: Mutex<Option<DeviceId>>,
    orientation: Mutex<DisplayOrientation>,
    brightness: AtomicBool,
}

pub struct DisplayDevice {
    info: DisplayInfo,
    driver: Box<dyn DisplayDriver>,
    state: DisplayState,
    current_mode: VideoMode,
    backlight: Option<BacklightControl>,
}

#[derive(Debug, Clone)]
pub struct DisplayInfo {
    name: &'static str,
    panel_type: PanelType,
    supported_modes: Vec<VideoMode>,
    native_mode: VideoMode,
    supported_orientations: OrientationSupport,
    physical_size: (u32, u32), // in millimeters
    touch_integrated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct VideoMode {
    width: u32,
    height: u32,
    refresh_rate: u32,
    pixel_format: PixelFormat,
}

pub trait DisplayDriver: Send + Sync {
    fn init(&mut self) -> Result<DisplayInfo, DisplayError>;
    fn set_mode(&mut self, mode: &VideoMode) -> Result<(), DisplayError>;
    fn set_orientation(&mut self, orientation: DisplayOrientation) -> Result<(), DisplayError>;
    fn get_framebuffer(&mut self) -> Result<&mut Framebuffer, DisplayError>;
    fn flush_region(&mut self, region: Option<Rectangle>) -> Result<(), DisplayError>;
    fn set_power_mode(&mut self, mode: PowerMode) -> Result<(), DisplayError>;
    fn set_brightness(&mut self, brightness: u8) -> Result<(), DisplayError>;
}

impl DisplayManager {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(BTreeMap::new()),
            active_display: Mutex::new(None),
            orientation: Mutex::new(DisplayOrientation::Portrait),
            brightness: AtomicBool::new(true),
        }
    }

    pub fn register_device(
        &self,
        device_id: DeviceId,
        driver: Box<dyn DisplayDriver>,
    ) -> Result<(), DisplayError> {
        let mut devices = self.devices.lock();

        let mut driver = driver;
        let info = driver.init()?;

        // Validate panel is suitable for mobile
        if !info.panel_type.is_mobile_compatible() {
            return Err(DisplayError::IncompatiblePanel);
        }

        let device = DisplayDevice {
            info,
            driver,
            state: DisplayState::Enabled,
            current_mode: info.native_mode,
            backlight: BacklightControl::new(),
        };

        devices.insert(device_id, device);

        // If this is the first display, make it active
        if self.active_display.lock().is_none() {
            *self.active_display.lock() = Some(device_id);
            self.setup_initial_display(device_id)?;
        }

        Ok(())
    }

    pub fn set_orientation(&self, orientation: DisplayOrientation) -> Result<(), DisplayError> {
        let devices = self.devices.lock();
        let active_id = self
            .active_display
            .lock()
            .ok_or(DisplayError::NoActiveDisplay)?;

        let device = devices
            .get(&active_id)
            .ok_or(DisplayError::DeviceNotFound)?;

        // Check if orientation is supported
        if !device.info.supported_orientations.supports(orientation) {
            return Err(DisplayError::UnsupportedOrientation);
        }

        // Update orientation
        *self.orientation.lock() = orientation;
        device.driver.set_orientation(orientation)?;

        // Notify system of orientation change
        self.handle_orientation_change(orientation)?;

        Ok(())
    }

    pub fn set_brightness(&self, level: u8) -> Result<(), DisplayError> {
        let devices = self.devices.lock();
        let active_id = self
            .active_display
            .lock()
            .ok_or(DisplayError::NoActiveDisplay)?;

        let device = devices
            .get(&active_id)
            .ok_or(DisplayError::DeviceNotFound)?;

        if let Some(backlight) = &device.backlight {
            backlight.set_brightness(level)?;
            self.brightness.store(level > 0, Ordering::SeqCst);
        }

        Ok(())
    }

    pub fn handle_ambient_light_change(&self, light_level: u16) -> Result<(), DisplayError> {
        // Auto-adjust brightness based on ambient light
        let brightness = self.calculate_optimal_brightness(light_level);
        self.set_brightness(brightness)?;
        Ok(())
    }

    fn calculate_optimal_brightness(&self, ambient: u16) -> u8 {
        // Implement brightness curve based on ambient light
        let base_level = (ambient as f32 / MAX_AMBIENT_LIGHT as f32) * 255.0;
        let adjusted = base_level * BRIGHTNESS_CURVE_FACTOR;
        min(max(adjusted as u8, MIN_BRIGHTNESS), MAX_BRIGHTNESS)
    }

    pub fn handle_power_event(&self, event: PowerEvent) -> Result<(), DisplayError> {
        match event {
            PowerEvent::Suspend => {
                self.set_power_mode(PowerMode::Suspend)?;
            }
            PowerEvent::Resume => {
                self.set_power_mode(PowerMode::On)?;
                // Restore previous brightness
                if self.brightness.load(Ordering::SeqCst) {
                    self.restore_brightness()?;
                }
            }
            PowerEvent::LowBattery => {
                // Reduce brightness to save power
                self.set_brightness(LOW_BATTERY_BRIGHTNESS)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisplayOrientation {
    Portrait,
    PortraitFlipped,
    Landscape,
    LandscapeFlipped,
}

#[derive(Debug, Clone, Copy)]
pub enum PanelType {
    LCD,
    OLED,
    AMOLED,
    MiniLED,
}

#[derive(Debug, Clone, Copy)]
pub enum PowerMode {
    On,
    Suspend,
    Off,
}

#[derive(Debug)]
pub enum DisplayError {
    DeviceNotFound,
    NoActiveDisplay,
    UnsupportedMode,
    UnsupportedOrientation,
    IncompatiblePanel,
    BacklightError,
    HardwareError,
}

// Constants for mobile displays
const MIN_BRIGHTNESS: u8 = 1;
const MAX_BRIGHTNESS: u8 = 255;
const LOW_BATTERY_BRIGHTNESS: u8 = 85; // 33% brightness
const MAX_AMBIENT_LIGHT: u16 = 65535;
const BRIGHTNESS_CURVE_FACTOR: f32 = 0.8;
const AUTO_BRIGHTNESS_UPDATE_INTERVAL: u64 = 500; // ms

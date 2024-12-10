// src/drivers/input/mod.rs
use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct InputManager {
    touch_devices: Mutex<BTreeMap<DeviceId, TouchDevice>>,
    pointer_devices: Mutex<BTreeMap<DeviceId, PointerDevice>>,
    input_handlers: Mutex<Vec<Box<dyn InputHandler>>>,
}

#[derive(Debug, Clone, Copy)]
pub struct TouchEvent {
    id: TouchId,
    position: Point,
    pressure: Option<f32>,
    size: Option<f32>,
    event_type: TouchEventType,
    timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PointerEvent {
    position: Point,
    buttons: ButtonState,
    scroll: Option<(f32, f32)>,
    event_type: PointerEventType,
    timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct TouchDevice {
    info: TouchDeviceInfo,
    capabilities: TouchCapabilities,
    state: DeviceState,
    active_touches: BTreeMap<TouchId, TouchPoint>,
}

#[derive(Debug, Clone)]
pub struct PointerDevice {
    info: PointerDeviceInfo,
    capabilities: PointerCapabilities,
    state: DeviceState,
    cursor_visible: bool,
}

impl InputManager {
    pub fn new() -> Self {
        Self {
            touch_devices: Mutex::new(BTreeMap::new()),
            pointer_devices: Mutex::new(BTreeMap::new()),
            input_handlers: Mutex::new(Vec::new()),
        }
    }

    pub fn register_touch_device(
        &self,
        device_id: DeviceId,
        info: TouchDeviceInfo,
    ) -> Result<(), InputError> {
        let device = TouchDevice {
            info,
            capabilities: TouchCapabilities::detect(&info),
            state: DeviceState::Ready,
            active_touches: BTreeMap::new(),
        };

        self.touch_devices.lock().insert(device_id, device);
        Ok(())
    }

    pub fn register_pointer_device(
        &self,
        device_id: DeviceId,
        info: PointerDeviceInfo,
    ) -> Result<(), InputError> {
        let device = PointerDevice {
            info,
            capabilities: PointerCapabilities::detect(&info),
            state: DeviceState::Ready,
            cursor_visible: false, // Hidden by default on touch devices
        };

        self.pointer_devices.lock().insert(device_id, device);

        // Only show cursor if this is the first pointer device
        if self.pointer_devices.lock().len() == 1 {
            self.show_cursor(true)?;
        }

        Ok(())
    }

    pub fn handle_touch_event(
        &self,
        device_id: DeviceId,
        event: TouchEvent,
    ) -> Result<(), InputError> {
        let mut devices = self.touch_devices.lock();
        let device = devices
            .get_mut(&device_id)
            .ok_or(InputError::DeviceNotFound)?;

        // Update touch state
        match event.event_type {
            TouchEventType::Down => {
                device
                    .active_touches
                    .insert(event.id, TouchPoint::from(event));
            }
            TouchEventType::Move => {
                if let Some(touch) = device.active_touches.get_mut(&event.id) {
                    touch.update(event);
                }
            }
            TouchEventType::Up => {
                device.active_touches.remove(&event.id);
            }
        }

        // Notify handlers
        for handler in self.input_handlers.lock().iter_mut() {
            handler.handle_touch(event)?;
        }

        Ok(())
    }

    pub fn handle_pointer_event(
        &self,
        device_id: DeviceId,
        event: PointerEvent,
    ) -> Result<(), InputError> {
        let devices = self.pointer_devices.lock();
        let device = devices.get(&device_id).ok_or(InputError::DeviceNotFound)?;

        // Show cursor if it was hidden
        if !device.cursor_visible {
            self.show_cursor(true)?;
        }

        // Update cursor position
        if device.capabilities.absolute_positioning {
            self.set_cursor_position(event.position.x as i32, event.position.y as i32)?;
        } else {
            // Handle relative movement
            self.update_cursor_position_relative(event.position.x as i32, event.position.y as i32)?;
        }

        // Notify handlers
        for handler in self.input_handlers.lock().iter_mut() {
            handler.handle_pointer(event)?;
        }

        Ok(())
    }

    fn show_cursor(&self, visible: bool) -> Result<(), InputError> {
        // Only show/hide cursor if we have any pointer devices
        if !self.pointer_devices.lock().is_empty() {
            // Update cursor visibility through display manager
            display::get_display_manager().set_cursor_visible(visible)?;

            // Update state for all pointer devices
            for device in self.pointer_devices.lock().values_mut() {
                device.cursor_visible = visible;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchEventType {
    Down,
    Move,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PointerEventType {
    Move,
    ButtonPress,
    ButtonRelease,
    Scroll,
}

#[derive(Debug)]
pub enum InputError {
    DeviceNotFound,
    InvalidOperation,
    HardwareError,
}

// Constants
const MAX_TOUCH_POINTS: usize = 10;
const CURSOR_FADE_TIMEOUT: u64 = 3000; // Hide cursor after 3 seconds of inactivity

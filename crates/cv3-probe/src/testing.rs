//! Fakes for the USB layer, used only by unit tests.

use std::cell::RefCell;
use std::rc::Rc;

use crate::discovery::{FoundSensor, SensorDevice, UsbBackend, UsbError};
use crate::layout::{EndpointDescriptor, InterfaceDescriptor, TransferType};
use crate::signals::SignalFlag;

/// The sensor the ticket's hardware reports: bus 3, port 8.
pub fn sensor() -> FoundSensor {
    FoundSensor {
        vendor: 0x0a5c,
        product: 0x5843,
        bus: 3,
        port_chain: vec![8],
    }
}

/// The layout the sensor's real descriptor carries.
pub fn sensor_interface() -> InterfaceDescriptor {
    InterfaceDescriptor {
        number: 0,
        class: 0xfe,
        endpoints: vec![
            EndpointDescriptor {
                address: 0x01,
                transfer: TransferType::Bulk,
            },
            EndpointDescriptor {
                address: 0x81,
                transfer: TransferType::Bulk,
            },
            EndpointDescriptor {
                address: 0x85,
                transfer: TransferType::Interrupt,
            },
        ],
    }
}

/// A backend whose every step can fail, and which records the calls it received.
pub struct FakeUsb {
    pub devices: Vec<FoundSensor>,
    pub enumerate_error: Option<UsbError>,
    pub open_error: Option<UsbError>,
    pub claim_error: Option<UsbError>,
    pub descriptor: InterfaceDescriptor,
    pub descriptor_error: Option<UsbError>,
    pub release_error: Option<UsbError>,
    pub signal_after_enumerate: Option<SignalFlag>,
    pub signal_after_descriptor: Option<SignalFlag>,
    log: Rc<RefCell<Vec<&'static str>>>,
}

impl Default for FakeUsb {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            enumerate_error: None,
            open_error: None,
            claim_error: None,
            descriptor: sensor_interface(),
            descriptor_error: None,
            release_error: None,
            signal_after_enumerate: None,
            signal_after_descriptor: None,
            log: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl FakeUsb {
    pub fn with_sensor() -> Self {
        Self {
            devices: vec![sensor()],
            ..Self::default()
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.log.borrow().clone()
    }

    fn record(&self, call: &'static str) {
        self.log.borrow_mut().push(call);
    }
}

impl UsbBackend for FakeUsb {
    fn enumerate(&mut self) -> Result<Vec<FoundSensor>, UsbError> {
        self.record("enumerate");
        if let Some(flag) = &self.signal_after_enumerate {
            flag.raise(2);
        }
        match &self.enumerate_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.devices.clone()),
        }
    }

    fn open(&mut self, _sensor: &FoundSensor) -> Result<Box<dyn SensorDevice>, UsbError> {
        self.record("open");
        if let Some(error) = &self.open_error {
            return Err(error.clone());
        }
        Ok(Box::new(FakeDevice {
            log: Rc::clone(&self.log),
            claim_error: self.claim_error.clone(),
            descriptor: self.descriptor.clone(),
            descriptor_error: self.descriptor_error.clone(),
            release_error: self.release_error.clone(),
            signal_after_descriptor: self.signal_after_descriptor.clone(),
        }))
    }
}

struct FakeDevice {
    log: Rc<RefCell<Vec<&'static str>>>,
    claim_error: Option<UsbError>,
    descriptor: InterfaceDescriptor,
    descriptor_error: Option<UsbError>,
    release_error: Option<UsbError>,
    signal_after_descriptor: Option<SignalFlag>,
}

impl FakeDevice {
    fn record(&self, call: &'static str) {
        self.log.borrow_mut().push(call);
    }
}

impl SensorDevice for FakeDevice {
    fn claim_interface(&mut self, _interface: u8) -> Result<(), UsbError> {
        self.record("claim");
        match &self.claim_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn interface_descriptor(&mut self, _interface: u8) -> Result<InterfaceDescriptor, UsbError> {
        self.record("descriptor");
        if let Some(flag) = &self.signal_after_descriptor {
            flag.raise(2);
        }
        match &self.descriptor_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.descriptor.clone()),
        }
    }

    fn release_interface(&mut self, _interface: u8) -> Result<(), UsbError> {
        self.record("release");
        match &self.release_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl Drop for FakeDevice {
    fn drop(&mut self) {
        self.record("close");
    }
}

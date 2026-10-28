//! Fakes for the USB layer, used only by unit tests.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cv3_core::frame;
use cv3_core::proto::{attr, cmd};

use crate::discovery::{FoundSensor, SensorDevice, UsbBackend, UsbError};
use crate::exchange::{ANNOUNCEMENT_LEN, Reply, UsbIo};
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
    pub challenge_status: u32,
    pub response_status: u32,
    pub challenge_body: Option<Vec<u8>>,
    /// Status the scripted sensor answers the wrapped `0x02` open with.
    pub open_status: u32,
    /// If set, the scripted sensor fails the wrapped `0x02` command in the transport.
    pub open_command_error: Option<UsbError>,
    /// If set, the scripted sensor fails the plain `0x04` close in the transport.
    pub close_command_error: Option<UsbError>,
    /// If set, the scripted sensor answers `0x04` with this body instead of no body.
    pub close_body: Option<Vec<u8>>,
    pub sent: Rc<RefCell<Vec<Vec<u8>>>>,
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
            challenge_status: 0,
            response_status: 0,
            challenge_body: None,
            open_status: 0,
            open_command_error: None,
            close_command_error: None,
            close_body: None,
            sent: Rc::new(RefCell::new(Vec::new())),
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

    fn open_command(&mut self, _sensor: &FoundSensor) -> Result<Box<dyn UsbIo>, UsbError> {
        self.record("open-command");
        if let Some(error) = &self.open_error {
            return Err(error.clone());
        }
        Ok(Box::new(HandshakeSensor {
            sent: Rc::clone(&self.sent),
            challenge: self.challenge_body.clone(),
            challenge_status: self.challenge_status,
            response_status: self.response_status,
            open_status: self.open_status,
            open_command_error: self.open_command_error.clone(),
            close_command_error: self.close_command_error.clone(),
            close_body: self.close_body.clone(),
            pending: None,
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

/// The handle the scripted sensor answers with.
pub const TEST_HANDLE: u32 = 0x1122_3344;

/// A fixed 20-byte device nonce for scripted replies.
pub const DEVICE_NONCE: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];

/// The P-256 generator, a valid device public key for synthetic frames.
pub const DEVICE_PUBLIC: [u8; 64] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// A scripted sensor that answers the `0x23` / `0x24` / `0x02` / `0x04` frames, so the probe's
/// whole handshake and secure-session lifecycle run offline. It records every frame it was sent.
pub struct HandshakeSensor {
    pub sent: Rc<RefCell<Vec<Vec<u8>>>>,
    pub challenge: Option<Vec<u8>>,
    pub challenge_status: u32,
    pub response_status: u32,
    pub open_status: u32,
    pub open_command_error: Option<UsbError>,
    pub close_command_error: Option<UsbError>,
    pub close_body: Option<Vec<u8>>,
    pending: Option<Reply>,
}

impl HandshakeSensor {
    fn reply_to(&self, frame: &[u8]) -> Reply {
        let command = u16::from_le_bytes([
            frame.get(8).copied().unwrap_or(0),
            frame.get(9).copied().unwrap_or(0),
        ]);
        match command {
            cmd::CHALLENGE => {
                let body = self.challenge.clone().unwrap_or_else(|| {
                    let mut param = [0u8; 148];
                    param[..64].copy_from_slice(&DEVICE_PUBLIC);
                    param[64..128].fill(0xcc);
                    param[128..].copy_from_slice(&DEVICE_NONCE);
                    frame::build_plain_reply(
                        cmd::CHALLENGE,
                        attr::CHALLENGE,
                        TEST_HANDLE,
                        self.challenge_status,
                        &param,
                    )
                });
                Reply { status: 0, body }
            }
            cmd::CHALLENGE_RESPONSE => Reply {
                status: 0,
                body: frame::build_plain_reply(
                    cmd::CHALLENGE_RESPONSE,
                    attr::CHALLENGE_RESPONSE,
                    TEST_HANDLE,
                    self.response_status,
                    &[],
                ),
            },
            cmd::OPEN_SESSION => Reply {
                status: 0,
                body: frame::build_plain_reply(
                    cmd::OPEN_SESSION,
                    attr::SESSION,
                    TEST_HANDLE,
                    self.open_status,
                    &[],
                ),
            },
            cmd::CLOSE_SESSION => Reply {
                status: 0,
                body: self.close_body.clone().unwrap_or_default(),
            },
            _ => Reply {
                status: 0,
                body: Vec::new(),
            },
        }
    }
}

impl UsbIo for HandshakeSensor {
    fn out(&mut self, frame: &[u8]) -> Result<(), UsbError> {
        self.sent.borrow_mut().push(frame.to_vec());
        let command = u16::from_le_bytes([
            frame.get(8).copied().unwrap_or(0),
            frame.get(9).copied().unwrap_or(0),
        ]);
        match command {
            cmd::OPEN_SESSION => {
                if let Some(error) = &self.open_command_error {
                    return Err(error.clone());
                }
            }
            cmd::CLOSE_SESSION => {
                if let Some(error) = &self.close_command_error {
                    return Err(error.clone());
                }
            }
            _ => {}
        }
        self.pending = Some(self.reply_to(frame));
        Ok(())
    }

    fn read_interrupt(&mut self, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let reply = self.pending.as_ref().expect("out ran first");
        let mut announcement = [0u8; ANNOUNCEMENT_LEN];
        announcement[..4].copy_from_slice(&reply.status.to_le_bytes());
        announcement[4..].copy_from_slice(&(reply.body.len() as u32).to_le_bytes());
        Ok(announcement.to_vec())
    }

    fn read_bulk(&mut self, _len: usize, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
        Ok(self.pending.as_ref().expect("out ran first").body.clone())
    }

    fn cancel_finger_wait(&mut self) {}
}

//! Fakes for the USB layer, used only by unit tests.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cv3_core::crypto;
use cv3_core::frame;
use cv3_core::proto::{attr, cmd, interrupt};

use crate::discovery::{FoundSensor, SensorDevice, UsbBackend, UsbError};
use crate::exchange::{ANNOUNCEMENT_LEN, Reply, UsbIo};
use crate::layout::{EndpointDescriptor, InterfaceDescriptor, TransferType};
use crate::signals::{Shutdown, SignalFlag};

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
    /// If set, the scripted sensor fails the plain `0x23` challenge in the transport.
    pub challenge_command_error: Option<UsbError>,
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
    /// Status the scripted sensor answers the wrapped `0x66` arm with.
    pub arm_status: u32,
    /// Per-arm statuses consumed in order before falling back to `arm_status`.
    pub arm_statuses: Vec<u32>,
    /// If set, the decrypted plaintext of the `0x66` reply; by default it carries `SAMPLE_HASH`.
    pub arm_plaintext: Option<Vec<u8>>,
    /// If set, the scripted sensor fails the wrapped `0x66` command in the transport.
    pub arm_command_error: Option<UsbError>,
    /// If set, the scripted sensor fails the sessionless `0x68` command in the transport.
    pub cancel_command_error: Option<UsbError>,
    /// Status the scripted sensor answers the wrapped `0x6d` discard with.
    pub discard_status: u32,
    /// If set, the scripted sensor fails the `0x6d` discard in the transport.
    pub discard_command_error: Option<UsbError>,
    /// Status the scripted sensor answers the plain `0x8a` start with.
    pub start_status: u32,
    /// If set, the scripted sensor fails the plain `0x8a` start in the transport.
    pub start_command_error: Option<UsbError>,
    /// Status the scripted sensor answers a `0x6c` update with when `update_statuses` is empty.
    pub update_status: u32,
    /// Per-update statuses consumed in order before falling back to `update_status`.
    pub update_statuses: Vec<u32>,
    /// If set, the scripted sensor fails the `0x6c` update in the transport.
    pub update_command_error: Option<UsbError>,
    /// After this many accepted updates, the `0x6c` reply carries `enrolment_id`.
    pub completion_after: Option<usize>,
    /// The 20-byte enrolment id the scripted completion carries.
    pub enrolment_id: [u8; 20],
    /// Status the scripted sensor answers the wrapped `0x6e` commit with.
    pub commit_status: u32,
    /// If set, the scripted sensor fails the `0x6e` commit in the transport.
    pub commit_command_error: Option<UsbError>,
    /// Status the scripted sensor answers the wrapped `0x73` match with.
    pub match_status: u32,
    /// If set, the decrypted plaintext of the `0x73` reply; by default it carries a match and
    /// `MATCH_VALUE` at `+32`.
    pub match_plaintext: Option<Vec<u8>>,
    /// If set, the scripted sensor fails the wrapped `0x73` match in the transport.
    pub match_command_error: Option<UsbError>,
    /// The decrypted TLV of every `0x73` request the scripted sensor received, in order.
    pub match_tlvs: Rc<RefCell<Vec<Vec<u8>>>>,
    /// What the finger wait delivers. `None` is a genuine `0x03` finger event.
    pub finger_event: Option<Result<Vec<u8>, UsbError>>,
    /// Per-wait finger results consumed in order before falling back to `finger_event`, so a test
    /// can let an enrolment's touches succeed and fail only the confirmation one.
    pub finger_events: Vec<Result<Vec<u8>, UsbError>>,
    /// Raised when the scripted sensor sends the `0x24` response, as a signal mid-command would be.
    pub signal_during_command: Option<SignalFlag>,
    /// Raised when the finger wait starts, as a signal mid-wait would be.
    pub signal_during_finger: Option<SignalFlag>,
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
            challenge_command_error: None,
            response_status: 0,
            challenge_body: None,
            open_status: 0,
            open_command_error: None,
            close_command_error: None,
            close_body: None,
            arm_status: 0,
            arm_statuses: Vec::new(),
            arm_plaintext: None,
            arm_command_error: None,
            cancel_command_error: None,
            discard_status: 0,
            discard_command_error: None,
            start_status: 0,
            start_command_error: None,
            update_status: 0x8f,
            update_statuses: Vec::new(),
            update_command_error: None,
            completion_after: None,
            enrolment_id: ENROLMENT_ID,
            commit_status: 0,
            commit_command_error: None,
            match_status: 0,
            match_plaintext: None,
            match_command_error: None,
            match_tlvs: Rc::new(RefCell::new(Vec::new())),
            finger_event: None,
            finger_events: Vec::new(),
            signal_during_command: None,
            signal_during_finger: None,
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

    fn open_command(
        &mut self,
        _sensor: &FoundSensor,
        cancellation: Option<SignalFlag>,
    ) -> Result<Box<dyn UsbIo>, UsbError> {
        self.record("open-command");
        if let Some(error) = &self.open_error {
            return Err(error.clone());
        }
        Ok(Box::new(HandshakeSensor {
            sent: Rc::clone(&self.sent),
            challenge: self.challenge_body.clone(),
            challenge_status: self.challenge_status,
            challenge_command_error: self.challenge_command_error.clone(),
            response_status: self.response_status,
            open_status: self.open_status,
            open_command_error: self.open_command_error.clone(),
            close_command_error: self.close_command_error.clone(),
            close_body: self.close_body.clone(),
            arm_status: self.arm_status,
            arm_statuses: self.arm_statuses.clone(),
            arm_plaintext: self.arm_plaintext.clone(),
            arm_command_error: self.arm_command_error.clone(),
            cancel_command_error: self.cancel_command_error.clone(),
            discard_status: self.discard_status,
            discard_command_error: self.discard_command_error.clone(),
            start_status: self.start_status,
            start_command_error: self.start_command_error.clone(),
            update_status: self.update_status,
            update_statuses: self.update_statuses.clone(),
            update_command_error: self.update_command_error.clone(),
            completion_after: self.completion_after,
            enrolment_id: self.enrolment_id,
            commit_status: self.commit_status,
            commit_command_error: self.commit_command_error.clone(),
            match_status: self.match_status,
            match_plaintext: self.match_plaintext.clone(),
            match_command_error: self.match_command_error.clone(),
            match_tlvs: Rc::clone(&self.match_tlvs),
            accepted_updates: 0,
            finger_event: self.finger_event.clone(),
            finger_events: self.finger_events.clone(),
            signal_during_command: self.signal_during_command.clone(),
            signal_during_finger: self.signal_during_finger.clone(),
            cancellation,
            session_key: None,
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

/// The 20-byte sample hash the scripted `0x66` reply carries.
pub const SAMPLE_HASH: [u8; 20] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23,
];

/// The 20-byte id the scripted `0x6c` reply carries when it completes the enrolment.
pub const ENROLMENT_ID: [u8; 20] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3,
];

/// The 20-byte value the scripted `0x73` reply carries at plaintext `+32`.
pub const MATCH_VALUE: [u8; 20] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3,
];

/// A scripted sensor that answers the `0x23` / `0x24` / `0x02` / `0x66` / `0x68` / `0x04` frames,
/// so the probe's whole handshake, secure-session and capture lifecycle run offline. It records
/// every frame it was sent.
///
/// The device public key is the P-256 generator, so the device's private scalar is 1 and the fake
/// can derive the session key from the host public key it receives: `ECDH(1, hostPub)` is
/// `hostPub`, whose X coordinate is the first 32 bytes of the uncompressed point.
pub struct HandshakeSensor {
    pub sent: Rc<RefCell<Vec<Vec<u8>>>>,
    pub challenge: Option<Vec<u8>>,
    pub challenge_status: u32,
    pub challenge_command_error: Option<UsbError>,
    pub response_status: u32,
    pub open_status: u32,
    pub open_command_error: Option<UsbError>,
    pub close_command_error: Option<UsbError>,
    pub close_body: Option<Vec<u8>>,
    pub arm_status: u32,
    pub arm_statuses: Vec<u32>,
    pub arm_plaintext: Option<Vec<u8>>,
    pub arm_command_error: Option<UsbError>,
    pub cancel_command_error: Option<UsbError>,
    pub discard_status: u32,
    pub discard_command_error: Option<UsbError>,
    pub start_status: u32,
    pub start_command_error: Option<UsbError>,
    pub update_status: u32,
    pub update_statuses: Vec<u32>,
    pub update_command_error: Option<UsbError>,
    pub completion_after: Option<usize>,
    pub enrolment_id: [u8; 20],
    pub commit_status: u32,
    pub commit_command_error: Option<UsbError>,
    pub match_status: u32,
    pub match_plaintext: Option<Vec<u8>>,
    pub match_command_error: Option<UsbError>,
    /// The decrypted TLV of each `0x73` request, recorded for the probe's tests.
    pub match_tlvs: Rc<RefCell<Vec<Vec<u8>>>>,
    pub accepted_updates: usize,
    pub finger_event: Option<Result<Vec<u8>, UsbError>>,
    pub finger_events: Vec<Result<Vec<u8>, UsbError>>,
    pub signal_during_command: Option<SignalFlag>,
    pub signal_during_finger: Option<SignalFlag>,
    /// The handle the CLI threaded in; a raised flag makes the finger wait report cancellation.
    pub cancellation: Option<SignalFlag>,
    pub session_key: Option<[u8; 16]>,
    pending: Option<Reply>,
}

impl HandshakeSensor {
    fn derive_session_key(&mut self, frame: &[u8]) {
        if frame.len() < 44 + 84 {
            return;
        }
        let host_nonce = &frame[44..64];
        let host_public = &frame[64..128];
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&host_public[..32]);
        let master = crypto::sha1(&shared);
        let mut input = [0u8; 60];
        input[..20].copy_from_slice(&master);
        input[20..40].copy_from_slice(&DEVICE_NONCE);
        input[40..60].copy_from_slice(host_nonce);
        let digest = crypto::sha1(&input);
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        self.session_key = Some(key);
    }

    /// Records the leading TLV of a wrapped `0x73` request, decrypting it with the session key.
    ///
    /// The TLV length is in the frame header at `PARAM_LEN_OFFSET`; the ciphertext follows the
    /// 44-byte header. Best effort: a malformed request records nothing rather than panicking.
    fn remember_match_tlv(&self, frame: &[u8]) {
        let Some(key) = self.session_key else {
            return;
        };
        if frame.len() < frame::HEADER_LEN + crypto::BLOCK_LEN {
            return;
        }
        let tlv_len = u32::from_le_bytes([
            frame[frame::PARAM_LEN_OFFSET],
            frame[frame::PARAM_LEN_OFFSET + 1],
            frame[frame::PARAM_LEN_OFFSET + 2],
            frame[frame::PARAM_LEN_OFFSET + 3],
        ]) as usize;
        let mut iv = [0u8; crypto::BLOCK_LEN];
        iv.copy_from_slice(&frame[frame::IV_OFFSET..frame::IV_OFFSET + crypto::BLOCK_LEN]);
        let Ok(plaintext) = crypto::decrypt_cbc(&key, &iv, &frame[frame::HEADER_LEN..]) else {
            return;
        };
        if tlv_len <= plaintext.len() {
            self.match_tlvs
                .borrow_mut()
                .push(plaintext[..tlv_len].to_vec());
        }
    }

    fn wrapped_body(
        &self,
        command: u16,
        attribute: u8,
        command_status: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let key = self
            .session_key
            .expect("the handshake derived a session key");
        let iv = [0x5au8; 16];
        let ciphertext = crypto::encrypt_cbc(&key, &iv, plaintext);
        let mut body = frame::build_wrapped(
            command,
            attribute,
            TEST_HANDLE,
            &iv,
            plaintext.len() as u32,
            &ciphertext,
        );
        body[20..24].copy_from_slice(&command_status.to_le_bytes());
        // The sensor stamps wrapped replies with the reply encoding, not the command encoding:
        // measured on hardware on 2026-10-28 (`0x66` answered with encoding `0x03`). The fake
        // mirrors the wire so the offline suite cannot stay green on an assumption the sensor
        // does not make.
        body[11] = cv3_core::proto::Encoding::WrappedReply as u8;
        body
    }

    fn arm_reply(&mut self) -> Reply {
        let command_status = if self.arm_statuses.is_empty() {
            self.arm_status
        } else {
            self.arm_statuses.remove(0)
        };
        let plaintext = self.arm_plaintext.clone().unwrap_or_else(|| {
            let mut plaintext = vec![0u8; 28];
            plaintext[4..8].copy_from_slice(&20u32.to_le_bytes());
            plaintext[8..].copy_from_slice(&SAMPLE_HASH);
            plaintext
        });
        Reply {
            status: 0,
            body: self.wrapped_body(cmd::ARM_CAPTURE, attr::CAPTURE, command_status, &plaintext),
        }
    }

    fn match_reply(&self) -> Reply {
        let plaintext = self.match_plaintext.clone().unwrap_or_else(|| {
            let mut plaintext = vec![0u8; 52];
            plaintext[8..12].copy_from_slice(&1u32.to_le_bytes());
            plaintext[32..52].copy_from_slice(&MATCH_VALUE);
            plaintext
        });
        Reply {
            status: 0,
            body: self.wrapped_body(cmd::MATCH, attr::CAPTURE, self.match_status, &plaintext),
        }
    }

    fn update_reply(&mut self) -> Reply {
        let command_status = if self.update_statuses.is_empty() {
            self.update_status
        } else {
            self.update_statuses.remove(0)
        };
        if command_status == 0 || command_status == 0x8f {
            self.accepted_updates += 1;
        }
        let id = match self.completion_after {
            Some(after) if self.accepted_updates >= after && command_status != 0x8c => {
                self.enrolment_id
            }
            _ => SAMPLE_HASH,
        };
        let mut plaintext = vec![0u8; 8 + id.len()];
        plaintext[4..8].copy_from_slice(&(id.len() as u32).to_le_bytes());
        plaintext[8..].copy_from_slice(&id);
        Reply {
            status: 0,
            body: self.wrapped_body(
                cmd::UPDATE_ENROLMENT,
                attr::SESSION,
                command_status,
                &plaintext,
            ),
        }
    }

    fn reply_to(&mut self, frame: &[u8]) -> Reply {
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
            cmd::DISCARD_ENROLMENT => Reply {
                status: 0,
                body: self.wrapped_body(
                    cmd::DISCARD_ENROLMENT,
                    attr::SESSION,
                    self.discard_status,
                    &[],
                ),
            },
            cmd::START_ENROLMENT => Reply {
                status: self.start_status,
                body: Vec::new(),
            },
            cmd::UPDATE_ENROLMENT => self.update_reply(),
            cmd::COMMIT_ENROLMENT => Reply {
                status: 0,
                body: self.wrapped_body(
                    cmd::COMMIT_ENROLMENT,
                    attr::SESSION,
                    self.commit_status,
                    &[],
                ),
            },
            cmd::ARM_CAPTURE => self.arm_reply(),
            cmd::MATCH => self.match_reply(),
            cmd::CANCEL_CAPTURE => Reply {
                status: 0,
                body: Vec::new(),
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
            cmd::CHALLENGE => {
                if let Some(error) = &self.challenge_command_error {
                    return Err(error.clone());
                }
            }
            cmd::CHALLENGE_RESPONSE => {
                self.derive_session_key(frame);
                if let Some(flag) = &self.signal_during_command {
                    flag.raise(signal_hook::consts::signal::SIGINT);
                }
            }
            cmd::OPEN_SESSION => {
                if let Some(error) = &self.open_command_error {
                    return Err(error.clone());
                }
            }
            cmd::DISCARD_ENROLMENT => {
                if let Some(error) = &self.discard_command_error {
                    return Err(error.clone());
                }
            }
            cmd::START_ENROLMENT => {
                if let Some(error) = &self.start_command_error {
                    return Err(error.clone());
                }
            }
            cmd::UPDATE_ENROLMENT => {
                if let Some(error) = &self.update_command_error {
                    return Err(error.clone());
                }
            }
            cmd::COMMIT_ENROLMENT => {
                if let Some(error) = &self.commit_command_error {
                    return Err(error.clone());
                }
            }
            cmd::ARM_CAPTURE => {
                if let Some(error) = &self.arm_command_error {
                    return Err(error.clone());
                }
            }
            cmd::MATCH => {
                if let Some(error) = &self.match_command_error {
                    return Err(error.clone());
                }
                self.remember_match_tlv(frame);
            }
            cmd::CANCEL_CAPTURE => {
                if let Some(error) = &self.cancel_command_error {
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

    fn read_finger(&mut self, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
        if let Some(flag) = &self.signal_during_finger {
            flag.raise(signal_hook::consts::signal::SIGINT);
        }
        if self
            .cancellation
            .as_ref()
            .and_then(Shutdown::signalled)
            .is_some()
        {
            // The real transport polls the same handle in slices and returns Cancelled.
            return Err(UsbError::Cancelled);
        }
        let scheduled = if self.finger_events.is_empty() {
            None
        } else {
            Some(self.finger_events.remove(0))
        };
        match scheduled.or_else(|| self.finger_event.clone()) {
            Some(result) => result,
            None => Ok(interrupt::FINGER.to_le_bytes().to_vec()),
        }
    }
}

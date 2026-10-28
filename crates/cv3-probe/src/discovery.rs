//! Finding, opening and releasing the sensor.
//!
//! Every USB call sits behind [`UsbBackend`] and [`SensorDevice`], so the "not found", "busy" and
//! "permission denied" paths are exercised with fakes and no hardware. The real implementation is
//! in [`crate::nusb_backend`].
//!
//! The claim is owned by a guard inside [`probe`]: it is released exactly once, on success, on any
//! error, and when a shutdown signal unwinds the flow.

use core::fmt;

use cv3_core::proto::{PRODUCT_ID, VENDOR_ID};

use crate::exchange::{Exchange, UsbIo};
use crate::layout::{EndpointLayout, InterfaceDescriptor, LayoutError, SENSOR_INTERFACE, validate};
use crate::signals::{Shutdown, SignalFlag};
pub use crate::usb::UsbError;

/// A device the OS reported, before it is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSensor {
    pub vendor: u16,
    pub product: u16,
    pub bus: u8,
    /// USB port path from the root hub, outermost port first.
    pub port_chain: Vec<u8>,
}

impl FoundSensor {
    pub fn is_sensor(&self) -> bool {
        self.vendor == VENDOR_ID && self.product == PRODUCT_ID
    }

    /// The stable one-line location `cvctl devices` prints.
    pub fn location(&self) -> String {
        let port = if self.port_chain.is_empty() {
            "?".to_owned()
        } else {
            self.port_chain
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".")
        };
        format!(
            "vendor {:04x} product {:04x} bus {} port {port}",
            self.vendor, self.product, self.bus
        )
    }
}

/// An opened device. The implementation closes the device when dropped.
pub trait SensorDevice {
    fn claim_interface(&mut self, interface: u8) -> Result<(), UsbError>;
    fn interface_descriptor(&mut self, interface: u8) -> Result<InterfaceDescriptor, UsbError>;
    fn release_interface(&mut self, interface: u8) -> Result<(), UsbError>;
}

/// Enumeration and opening, as the probe sees them.
pub trait UsbBackend {
    fn enumerate(&mut self) -> Result<Vec<FoundSensor>, UsbError>;
    fn open(&mut self, sensor: &FoundSensor) -> Result<Box<dyn SensorDevice>, UsbError>;

    /// Opens the sensor and claims interface 0 for command transfers, returning the transport the
    /// core drives. Backends that cannot carry commands leave this unimplemented.
    ///
    /// `cancellation` is the handle the transport polls during the finger wait, so a signal can
    /// abort that one transfer without touching a command transfer.
    fn open_command(
        &mut self,
        _sensor: &FoundSensor,
        _cancellation: Option<SignalFlag>,
    ) -> Result<Box<dyn UsbIo>, UsbError> {
        Err(UsbError::Other(
            "this USB backend has no command transport".to_owned(),
        ))
    }
}

/// An open, claimed command channel. Dropping it releases the interface.
pub struct CommandSession {
    io: Box<dyn UsbIo>,
}

impl CommandSession {
    /// The exchange every command goes through.
    pub fn exchange(&mut self) -> Exchange<'_> {
        Exchange::new(self.io.as_mut())
    }
}

/// The step a failure came from, so the message can say where it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Enumerating,
    Opening,
    Claiming,
    Describing,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Enumerating => "enumerating devices",
            Self::Opening => "opening the sensor",
            Self::Claiming => "claiming interface 0",
            Self::Describing => "reading the interface descriptor",
        };
        f.write_str(text)
    }
}

/// Why `cvctl devices` could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    NotFound,
    Busy,
    PermissionDenied,
    Multiple { count: usize },
    Layout(LayoutError),
    Backend { stage: Stage, error: UsbError },
    Release(UsbError),
    Interrupted(i32),
}

impl ProbeError {
    /// The process exit status this failure maps to.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NotFound => 2,
            Self::Busy => 3,
            Self::PermissionDenied => 4,
            Self::Interrupted(signal) => u8::try_from(128 + signal).unwrap_or(1),
            _ => 1,
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "sensor {VENDOR_ID:04x}:{PRODUCT_ID:04x} not found"),
            Self::Busy => write!(
                f,
                "sensor {VENDOR_ID:04x}:{PRODUCT_ID:04x} is busy: interface 0 is already claimed \
                 by another process (is fprintd running?)"
            ),
            Self::PermissionDenied => write!(
                f,
                "permission denied opening sensor {VENDOR_ID:04x}:{PRODUCT_ID:04x}: run as root"
            ),
            Self::Multiple { count } => write!(
                f,
                "found {count} sensors matching {VENDOR_ID:04x}:{PRODUCT_ID:04x}; expected exactly \
                 one"
            ),
            Self::Layout(error) => write!(f, "unexpected interface layout: {error}"),
            Self::Backend { stage, error } => write!(f, "{stage} failed: {error}"),
            Self::Release(error) => write!(f, "releasing interface 0 failed: {error}"),
            Self::Interrupted(signal) => write!(f, "interrupted by signal {signal}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// What a successful probe learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub sensor: FoundSensor,
    pub layout: EndpointLayout,
}

/// Picks the one device matching the sensor's ids.
pub fn select_sensor(devices: Vec<FoundSensor>) -> Result<FoundSensor, ProbeError> {
    let mut matching = devices.into_iter().filter(FoundSensor::is_sensor);
    let Some(sensor) = matching.next() else {
        return Err(ProbeError::NotFound);
    };
    let count = 1 + matching.count();
    if count > 1 {
        return Err(ProbeError::Multiple { count });
    }
    Ok(sensor)
}

/// Finds the sensor, opens it, claims interface 0, validates the endpoint layout and releases it.
///
/// The interface is claimed for exactly as long as this function needs it. On success the layout
/// is returned after the release; on any error, including a shutdown signal, the claim is dropped
/// before the error is returned.
pub fn probe(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
) -> Result<ProbeOutcome, ProbeError> {
    interrupted(shutdown)?;

    let devices = backend
        .enumerate()
        .map_err(|error| stage_error(Stage::Enumerating, error))?;
    let sensor = select_sensor(devices)?;

    interrupted(shutdown)?;
    let device = backend
        .open(&sensor)
        .map_err(|error| stage_error(Stage::Opening, error))?;
    let mut claimed = Claimed::new(device);

    interrupted(shutdown)?;
    claimed
        .claim()
        .map_err(|error| stage_error(Stage::Claiming, error))?;

    interrupted(shutdown)?;
    let descriptor = claimed
        .descriptor()
        .map_err(|error| stage_error(Stage::Describing, error))?;

    interrupted(shutdown)?;
    let layout = validate(&descriptor).map_err(ProbeError::Layout)?;

    interrupted(shutdown)?;
    claimed.release().map_err(ProbeError::Release)?;

    Ok(ProbeOutcome { sensor, layout })
}

/// Finds the sensor, opens it, claims interface 0 and leaves the command channel open.
///
/// This is the probe's entry point for every command subcommand. Unlike [`probe`], which releases
/// the interface after checking the descriptor, the returned [`CommandSession`] owns the claim
/// until it is dropped, so one session can carry a whole operation. The shutdown handle is
/// threaded into the transport so the finger wait can be cancelled without touching a command.
pub fn open_for_command(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
) -> Result<CommandSession, ProbeError> {
    interrupted(shutdown)?;

    let devices = backend
        .enumerate()
        .map_err(|error| stage_error(Stage::Enumerating, error))?;
    let sensor = select_sensor(devices)?;

    interrupted(shutdown)?;
    let io = backend
        .open_command(&sensor, shutdown.cancellation())
        .map_err(|error| stage_error(Stage::Opening, error))?;

    Ok(CommandSession { io })
}

/// A shutdown request turns into the same unwind as any other failure, so the guard releases.
fn interrupted(shutdown: &dyn Shutdown) -> Result<(), ProbeError> {
    match shutdown.signalled() {
        Some(signal) => Err(ProbeError::Interrupted(signal)),
        None => Ok(()),
    }
}

/// Classifies a USB failure. The three states an operator can act on keep their own error; the
/// rest say which step failed.
fn stage_error(stage: Stage, error: UsbError) -> ProbeError {
    match error {
        UsbError::NotFound => ProbeError::NotFound,
        UsbError::Busy => ProbeError::Busy,
        UsbError::PermissionDenied => ProbeError::PermissionDenied,
        other => ProbeError::Backend {
            stage,
            error: other,
        },
    }
}

/// Claims interface 0 and releases it exactly once, whichever way the flow ends.
struct Claimed {
    device: Box<dyn SensorDevice>,
    claimed: bool,
    released: bool,
}

impl Claimed {
    fn new(device: Box<dyn SensorDevice>) -> Self {
        Self {
            device,
            claimed: false,
            released: false,
        }
    }

    fn claim(&mut self) -> Result<(), UsbError> {
        self.device.claim_interface(SENSOR_INTERFACE)?;
        self.claimed = true;
        Ok(())
    }

    fn descriptor(&mut self) -> Result<InterfaceDescriptor, UsbError> {
        self.device.interface_descriptor(SENSOR_INTERFACE)
    }

    fn release(&mut self) -> Result<(), UsbError> {
        if !self.claimed || self.released {
            return Ok(());
        }
        // Mark first: a failed release must not be retried by `Drop`, which would turn one error
        // into two release attempts.
        self.released = true;
        self.device.release_interface(SENSOR_INTERFACE)
    }
}

impl Drop for Claimed {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{EndpointDescriptor, TransferType};
    use crate::signals::SignalFlag;
    use crate::testing::{FakeUsb, sensor};

    fn other_device() -> FoundSensor {
        FoundSensor {
            vendor: 0x1234,
            product: 0x5678,
            bus: 1,
            port_chain: vec![2],
        }
    }

    #[test]
    fn the_location_line_names_vendor_product_bus_and_port() {
        let found = FoundSensor {
            vendor: 0x0a5c,
            product: 0x5843,
            bus: 3,
            port_chain: vec![8],
        };

        assert_eq!(found.location(), "vendor 0a5c product 5843 bus 3 port 8");
    }

    #[test]
    fn an_unrelated_device_is_not_the_sensor() {
        assert!(!other_device().is_sensor());
    }

    #[test]
    fn selecting_ignores_unrelated_devices() {
        let picked =
            select_sensor(vec![other_device(), sensor()]).expect("one matching device is enough");

        assert_eq!(picked, sensor());
    }

    #[test]
    fn selecting_no_device_is_not_found() {
        assert_eq!(select_sensor(Vec::new()), Err(ProbeError::NotFound));
        assert_eq!(
            select_sensor(vec![other_device()]),
            Err(ProbeError::NotFound)
        );
    }

    #[test]
    fn selecting_two_sensors_is_ambiguous() {
        let second = FoundSensor {
            bus: 4,
            port_chain: vec![1],
            ..sensor()
        };

        assert_eq!(
            select_sensor(vec![sensor(), second]),
            Err(ProbeError::Multiple { count: 2 })
        );
    }

    #[test]
    fn a_successful_probe_claims_reads_and_releases() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let outcome = probe(&mut usb, &shutdown).expect("the fake presents the sensor");

        assert_eq!(outcome.sensor, sensor());
        assert_eq!(outcome.layout, EndpointLayout::SENSOR);
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn a_missing_sensor_is_not_opened() {
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        assert_eq!(probe(&mut usb, &shutdown), Err(ProbeError::NotFound));
        assert_eq!(usb.calls(), ["enumerate"]);
    }

    #[test]
    fn an_enumerate_error_names_its_stage_and_opens_nothing() {
        let mut usb = FakeUsb::with_sensor();
        usb.enumerate_error = Some(UsbError::Other("usbfs unreadable".into()));
        let shutdown = SignalFlag::new();

        assert_eq!(
            probe(&mut usb, &shutdown),
            Err(ProbeError::Backend {
                stage: Stage::Enumerating,
                error: UsbError::Other("usbfs unreadable".into()),
            })
        );
        assert_eq!(usb.calls(), ["enumerate"]);
    }

    #[test]
    fn opening_without_permission_reports_permission_denied() {
        let mut usb = FakeUsb::with_sensor();
        usb.open_error = Some(UsbError::PermissionDenied);
        let shutdown = SignalFlag::new();

        assert_eq!(
            probe(&mut usb, &shutdown),
            Err(ProbeError::PermissionDenied)
        );
        assert_eq!(usb.calls(), ["enumerate", "open"]);
    }

    #[test]
    fn a_interface_held_elsewhere_is_busy_and_is_not_released() {
        let mut usb = FakeUsb::with_sensor();
        usb.claim_error = Some(UsbError::Busy);
        let shutdown = SignalFlag::new();

        assert_eq!(probe(&mut usb, &shutdown), Err(ProbeError::Busy));
        // Claiming failed, so there is nothing of ours to release.
        assert_eq!(usb.calls(), ["enumerate", "open", "claim", "close"]);
    }

    #[test]
    fn a_descriptor_error_still_releases_the_claim() {
        let mut usb = FakeUsb::with_sensor();
        usb.descriptor_error = Some(UsbError::Other("broken descriptor".into()));
        let shutdown = SignalFlag::new();

        assert_eq!(
            probe(&mut usb, &shutdown),
            Err(ProbeError::Backend {
                stage: Stage::Describing,
                error: UsbError::Other("broken descriptor".into()),
            })
        );
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn a_layout_mismatch_is_reported_as_what_it_is_and_released() {
        let mut usb = FakeUsb::with_sensor();
        usb.descriptor.endpoints.push(EndpointDescriptor {
            address: 0x02,
            transfer: TransferType::Bulk,
        });
        let shutdown = SignalFlag::new();

        assert_eq!(
            probe(&mut usb, &shutdown),
            Err(ProbeError::Layout(LayoutError::UnexpectedEndpoint {
                address: 0x02
            }))
        );
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn a_failed_release_is_an_error_and_is_not_retried() {
        let mut usb = FakeUsb::with_sensor();
        usb.release_error = Some(UsbError::Disconnected);
        let shutdown = SignalFlag::new();

        assert_eq!(
            probe(&mut usb, &shutdown),
            Err(ProbeError::Release(UsbError::Disconnected))
        );
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn a_signal_before_opening_stops_without_touching_the_device() {
        let mut usb = FakeUsb::with_sensor();
        let flag = SignalFlag::new();
        usb.signal_after_enumerate = Some(flag.clone());

        assert_eq!(probe(&mut usb, &flag), Err(ProbeError::Interrupted(2)));
        assert_eq!(flag.get(), Some(2));
        assert_eq!(usb.calls(), ["enumerate"]);
    }

    #[test]
    fn a_signal_during_the_probe_releases_the_claim_before_returning() {
        let mut usb = FakeUsb::with_sensor();
        let flag = SignalFlag::new();
        usb.signal_after_descriptor = Some(flag.clone());

        assert_eq!(probe(&mut usb, &flag), Err(ProbeError::Interrupted(2)));
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }
}

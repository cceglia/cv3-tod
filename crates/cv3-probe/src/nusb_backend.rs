//! The real USB transport, over `nusb`.
//!
//! Discovery and descriptor reading are ordinary blocking nusb calls. Command transfers are not:
//! they are submitted and awaited with `wait_next_complete`, never with `transfer_blocking`, so a
//! timeout leaves the transfer in flight instead of cancelling it. Cancelling a bulk command
//! transfer is what deep-wedges this sensor, so a timed-out command deliberately abandons the
//! transfer and the process's own teardown closes the device.
//!
//! The finger wait is the exception: it is cancelled on timeout and its cancelled completion is
//! reaped, so the interrupt endpoint is left with nothing pending. That is why [`NusbIo`] never
//! marks itself poisoned on a finger timeout and still releases the interface normally.

use std::time::Duration;

use cv3_core::proto::{endpoint, timeout};
use nusb::MaybeFuture;
use nusb::descriptors::TransferType as NusbTransferType;
use nusb::transfer::{Bulk, In, Interrupt, Out, TransferError};

use crate::discovery::{FoundSensor, SensorDevice, UsbBackend};
use crate::exchange::UsbIo;
use crate::layout::{EndpointDescriptor, InterfaceDescriptor, TransferType};
use crate::usb::UsbError;

/// The sensor's USB backend.
pub struct NusbBackend;

impl Default for NusbBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NusbBackend {
    pub fn new() -> Self {
        Self
    }

    fn matching_device(sensor: &FoundSensor) -> Result<nusb::DeviceInfo, UsbError> {
        nusb::list_devices()
            .wait()
            .map_err(map_error)?
            .find(|device| {
                device.vendor_id() == sensor.vendor
                    && device.product_id() == sensor.product
                    && device.busnum() == sensor.bus
                    && device.port_chain() == sensor.port_chain.as_slice()
            })
            .ok_or(UsbError::NotFound)
    }
}

impl UsbBackend for NusbBackend {
    fn enumerate(&mut self) -> Result<Vec<FoundSensor>, UsbError> {
        let devices = nusb::list_devices().wait().map_err(map_error)?;
        Ok(devices
            .map(|device| FoundSensor {
                vendor: device.vendor_id(),
                product: device.product_id(),
                bus: device.busnum(),
                port_chain: device.port_chain().to_vec(),
            })
            .collect())
    }

    fn open(&mut self, sensor: &FoundSensor) -> Result<Box<dyn SensorDevice>, UsbError> {
        let info = Self::matching_device(sensor)?;
        let device = info.open().wait().map_err(map_error)?;
        Ok(Box::new(NusbDevice {
            device,
            interface: None,
        }))
    }

    fn open_command(&mut self, sensor: &FoundSensor) -> Result<Box<dyn UsbIo>, UsbError> {
        let info = Self::matching_device(sensor)?;
        let device = info.open().wait().map_err(map_error)?;
        let interface = device.claim_interface(0).wait().map_err(map_error)?;
        Ok(Box::new(NusbIo::new(interface)))
    }
}

struct NusbDevice {
    device: nusb::Device,
    /// Present exactly while interface 0 is claimed by us. Dropping it releases the claim.
    interface: Option<nusb::Interface>,
}

impl SensorDevice for NusbDevice {
    fn claim_interface(&mut self, interface: u8) -> Result<(), UsbError> {
        if self.interface.is_some() {
            return Ok(());
        }
        let claimed = self
            .device
            .claim_interface(interface)
            .wait()
            .map_err(map_error)?;
        self.interface = Some(claimed);
        Ok(())
    }

    fn interface_descriptor(&mut self, interface: u8) -> Result<InterfaceDescriptor, UsbError> {
        let configuration = self
            .device
            .active_configuration()
            .map_err(|error| UsbError::Other(error.to_string()))?;
        let descriptor = configuration
            .interface_alt_settings()
            .find(|alternate| {
                alternate.interface_number() == interface && alternate.alternate_setting() == 0
            })
            .ok_or(UsbError::NotFound)?;

        Ok(InterfaceDescriptor {
            number: descriptor.interface_number(),
            class: descriptor.class(),
            endpoints: descriptor
                .endpoints()
                .map(|endpoint| EndpointDescriptor {
                    address: endpoint.address(),
                    transfer: map_transfer_type(endpoint.transfer_type()),
                })
                .collect(),
        })
    }

    fn release_interface(&mut self, _interface: u8) -> Result<(), UsbError> {
        match self.interface.take() {
            Some(interface) => interface.release().wait().map_err(map_error),
            None => Ok(()),
        }
    }
}

/// A claimed interface wired to the three protocol endpoints.
///
/// A timed-out transfer is abandoned rather than cancelled: [`Self::poisoned`] makes the drop
/// skip the release, because releasing an interface with a pending command transfer would cancel
/// it. The process is expected to exit immediately after the error, and closing the device file
/// descriptor is then the teardown.
pub struct NusbIo {
    interface: Option<nusb::Interface>,
    poisoned: bool,
}

impl NusbIo {
    pub fn new(interface: nusb::Interface) -> Self {
        Self {
            interface: Some(interface),
            poisoned: false,
        }
    }

    fn interface(&self) -> Result<&nusb::Interface, UsbError> {
        self.interface
            .as_ref()
            .ok_or_else(|| UsbError::Other("USB interface is no longer open".to_owned()))
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl Drop for NusbIo {
    fn drop(&mut self) {
        if self.poisoned
            && let Some(interface) = self.interface.take()
        {
            // Do not release: that would abort the command transfer still in flight.
            std::mem::forget(interface);
        }
    }
}

impl UsbIo for NusbIo {
    fn out(&mut self, frame: &[u8]) -> Result<(), UsbError> {
        let interface = self.interface()?.clone();
        let mut pipe = interface
            .endpoint::<Bulk, Out>(endpoint::OUT)
            .map_err(map_error)?;
        pipe.submit(frame.to_vec().into());
        match pipe.wait_next_complete(Duration::from_millis(timeout::COMMAND_MS as u64)) {
            Some(completion) => completion.status.map_err(map_transfer),
            None => {
                std::mem::forget(pipe);
                self.poison();
                Err(UsbError::Timeout)
            }
        }
    }

    fn read_interrupt(&mut self, wait: Duration) -> Result<Vec<u8>, UsbError> {
        let interface = self.interface()?.clone();
        let mut pipe = interface
            .endpoint::<Interrupt, In>(endpoint::INTERRUPT)
            .map_err(map_error)?;
        let request = pipe.max_packet_size().max(1);
        pipe.submit(nusb::transfer::Buffer::new(request));
        match pipe.wait_next_complete(wait) {
            Some(completion) => {
                completion.status.map_err(map_transfer)?;
                Ok(completion.buffer[..completion.actual_len].to_vec())
            }
            None => {
                std::mem::forget(pipe);
                self.poison();
                Err(UsbError::Timeout)
            }
        }
    }

    fn read_bulk(&mut self, len: usize, wait: Duration) -> Result<Vec<u8>, UsbError> {
        let interface = self.interface()?.clone();
        let mut pipe = interface
            .endpoint::<Bulk, In>(endpoint::IN)
            .map_err(map_error)?;
        // nusb refuses an IN request that is not a multiple of the endpoint's packet size; the
        // extra bytes are never returned by a device that respects the announced length.
        let packet = pipe.max_packet_size().max(1);
        let request = len.div_ceil(packet) * packet;
        pipe.submit(nusb::transfer::Buffer::new(request));
        match pipe.wait_next_complete(wait) {
            Some(completion) => {
                completion.status.map_err(map_transfer)?;
                Ok(completion.buffer[..completion.actual_len].to_vec())
            }
            None => {
                std::mem::forget(pipe);
                self.poison();
                Err(UsbError::Timeout)
            }
        }
    }

    fn read_finger(&mut self, wait: Duration) -> Result<Vec<u8>, UsbError> {
        let interface = self.interface()?.clone();
        let mut pipe = interface
            .endpoint::<Interrupt, In>(endpoint::INTERRUPT)
            .map_err(map_error)?;
        let request = pipe.max_packet_size().max(1);
        pipe.submit(nusb::transfer::Buffer::new(request));
        match pipe.wait_next_complete(wait) {
            Some(completion) => {
                completion.status.map_err(map_transfer)?;
                Ok(completion.buffer[..completion.actual_len].to_vec())
            }
            None => {
                // The finger wait is the only cancellable transfer. Cancel it and reap the
                // cancelled completion, so nothing is left pending and the interface stays
                // healthy; unlike a timed-out command, this never poisons the device.
                pipe.cancel_all();
                let deadline =
                    std::time::Instant::now() + Duration::from_millis(timeout::TEARDOWN_MS as u64);
                while pipe.pending() > 0 {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() || pipe.wait_next_complete(remaining).is_none() {
                        break;
                    }
                }
                Err(UsbError::Timeout)
            }
        }
    }
}

/// Maps an enumeration, open or claim failure by what the operator can do about it.
fn map_error(error: nusb::Error) -> UsbError {
    match error.kind() {
        nusb::ErrorKind::Busy => UsbError::Busy,
        nusb::ErrorKind::PermissionDenied => UsbError::PermissionDenied,
        nusb::ErrorKind::NotFound => UsbError::NotFound,
        nusb::ErrorKind::Disconnected => UsbError::Disconnected,
        _ => UsbError::Other(error.to_string()),
    }
}

fn map_transfer(error: TransferError) -> UsbError {
    match error {
        TransferError::Cancelled => UsbError::Timeout,
        TransferError::Stall => UsbError::Stall,
        TransferError::Disconnected => UsbError::Disconnected,
        TransferError::InvalidArgument => UsbError::Other("invalid transfer argument".to_owned()),
        other => UsbError::Other(format!("USB transfer failed: {other:?}")),
    }
}

fn map_transfer_type(transfer: NusbTransferType) -> TransferType {
    match transfer {
        NusbTransferType::Control => TransferType::Control,
        NusbTransferType::Isochronous => TransferType::Isochronous,
        NusbTransferType::Bulk => TransferType::Bulk,
        NusbTransferType::Interrupt => TransferType::Interrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_failures_keep_their_distinct_meanings() {
        assert_eq!(map_transfer(TransferError::Cancelled), UsbError::Timeout);
        assert_eq!(map_transfer(TransferError::Stall), UsbError::Stall);
        assert_eq!(
            map_transfer(TransferError::Disconnected),
            UsbError::Disconnected
        );
    }

    #[test]
    fn descriptor_transfer_types_are_carried_through() {
        assert_eq!(
            map_transfer_type(NusbTransferType::Bulk),
            TransferType::Bulk
        );
        assert_eq!(
            map_transfer_type(NusbTransferType::Interrupt),
            TransferType::Interrupt
        );
    }
}

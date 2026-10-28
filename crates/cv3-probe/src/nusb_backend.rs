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
//!
//! The finger wait is also the only transfer that watches for a shutdown request. When the probe
//! is asked to stop, the wait is polled in short slices ([`CANCEL_POLL_MS`]); a raised flag
//! cancels the transfer, reaps the cancelled completion and reports [`UsbError::Cancelled`], which
//! the core turns into its own cancellation event and teardown. No command transfer takes this
//! path: `out`, `read_interrupt` and `read_bulk` never look at the cancellation handle.

use std::time::{Duration, Instant};

use cv3_core::proto::{endpoint, timeout};
use nusb::MaybeFuture;
use nusb::descriptors::TransferType as NusbTransferType;
use nusb::transfer::{Bulk, In, Interrupt, Out, TransferError};

use crate::discovery::{FoundSensor, SensorDevice, UsbBackend};
use crate::exchange::UsbIo;
use crate::layout::{EndpointDescriptor, InterfaceDescriptor, TransferType};
use crate::signals::SignalFlag;
use crate::usb::UsbError;

/// The longest a finger wait blocks before it checks for a shutdown request.
pub const CANCEL_POLL_MS: u64 = 100;

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

    fn open_command(
        &mut self,
        sensor: &FoundSensor,
        cancellation: Option<SignalFlag>,
    ) -> Result<Box<dyn UsbIo>, UsbError> {
        let info = Self::matching_device(sensor)?;
        let device = info.open().wait().map_err(map_error)?;
        let interface = device.claim_interface(0).wait().map_err(map_error)?;
        Ok(Box::new(NusbIo::new(interface, cancellation)))
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
    /// Polled only by the finger wait, never by a command transfer.
    cancellation: Option<SignalFlag>,
}

impl NusbIo {
    pub fn new(interface: nusb::Interface, cancellation: Option<SignalFlag>) -> Self {
        Self {
            interface: Some(interface),
            poisoned: false,
            cancellation,
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
        let mut transfer = InterruptTransfer { pipe };
        wait_for_finger(&mut transfer, wait, self.cancellation.as_ref())
    }
}

/// One submitted transfer that can be waited on in slices and cancelled.
///
/// This is the internal seam the polling logic is tested through: the real implementation wraps an
/// nusb interrupt endpoint, the tests wrap a fake that raises a signal and hands back completions.
trait PendingTransfer {
    /// Waits at most `wait` for the next completion.
    fn wait(&mut self, wait: Duration) -> Option<Result<Vec<u8>, UsbError>>;
    /// Cancels every pending transfer; their completions still arrive and must be reaped.
    fn cancel_all(&mut self);
    /// How many transfers are still pending.
    fn pending(&self) -> usize;
}

struct InterruptTransfer {
    pipe: nusb::Endpoint<Interrupt, In>,
}

impl PendingTransfer for InterruptTransfer {
    fn wait(&mut self, wait: Duration) -> Option<Result<Vec<u8>, UsbError>> {
        self.pipe.wait_next_complete(wait).map(|completion| {
            completion.status.map_err(map_transfer)?;
            Ok(completion.buffer[..completion.actual_len].to_vec())
        })
    }

    fn cancel_all(&mut self) {
        self.pipe.cancel_all();
    }

    fn pending(&self) -> usize {
        self.pipe.pending()
    }
}

/// Waits for the finger event in short slices, cancelling and reaping when asked to stop.
///
/// The transfer is left running between slices: no cancellation happens until the flag is raised
/// or the timeout expires. On either ending the cancelled completion is reaped, as the timeout path
/// has always done, so the interface stays usable.
fn wait_for_finger<T: PendingTransfer>(
    transfer: &mut T,
    wait: Duration,
    cancellation: Option<&SignalFlag>,
) -> Result<Vec<u8>, UsbError> {
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let slice = remaining.min(Duration::from_millis(CANCEL_POLL_MS));
        if let Some(result) = transfer.wait(slice) {
            return result;
        }
        if cancellation.is_some_and(|flag| flag.get().is_some()) {
            cancel_and_reap(transfer);
            return Err(UsbError::Cancelled);
        }
        if remaining.is_zero() {
            cancel_and_reap(transfer);
            return Err(UsbError::Timeout);
        }
    }
}

/// Cancels the transfer and drains its cancelled completion, bounded by the teardown timeout.
fn cancel_and_reap<T: PendingTransfer>(transfer: &mut T) {
    transfer.cancel_all();
    let deadline = Instant::now() + Duration::from_millis(timeout::TEARDOWN_MS as u64);
    while transfer.pending() > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || transfer.wait(remaining).is_none() {
            break;
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
    use std::collections::VecDeque;

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

    /// A submitted transfer whose completions are scripted, so the polling logic runs with no USB.
    struct FakeTransfer {
        completions: VecDeque<Option<Result<Vec<u8>, UsbError>>>,
        pending: usize,
        cancel_calls: usize,
        waits: Vec<Duration>,
        /// Raise `flag` on the 1-based wait number, as a signal arriving mid-wait would.
        raise_on_wait: Option<(usize, SignalFlag)>,
        /// The completion `cancel_all` makes available to be reaped.
        cancelled: Option<Result<Vec<u8>, UsbError>>,
    }

    impl FakeTransfer {
        fn empty(pending: usize) -> Self {
            Self {
                completions: VecDeque::new(),
                pending,
                cancel_calls: 0,
                waits: Vec::new(),
                raise_on_wait: None,
                cancelled: None,
            }
        }

        fn completing(result: Result<Vec<u8>, UsbError>) -> Self {
            let mut transfer = Self::empty(1);
            transfer.completions.push_back(Some(result));
            transfer
        }
    }

    impl PendingTransfer for FakeTransfer {
        fn wait(&mut self, wait: Duration) -> Option<Result<Vec<u8>, UsbError>> {
            self.waits.push(wait);
            if let Some((at, flag)) = &self.raise_on_wait
                && self.waits.len() == *at
            {
                flag.raise(signal_hook::consts::signal::SIGINT);
            }
            if let Some(next) = self.completions.pop_front() {
                return next;
            }
            if let Some(completion) = self.cancelled.take() {
                self.pending = 0;
                return Some(completion);
            }
            None
        }

        fn cancel_all(&mut self) {
            self.cancel_calls += 1;
            if self.pending > 0 {
                // A cancelled transfer still reports a completion; the wait must reap it.
                self.cancelled = Some(Err(UsbError::Timeout));
            }
        }

        fn pending(&self) -> usize {
            self.pending
        }
    }

    #[test]
    fn a_finger_completion_is_returned_without_cancelling_anything() {
        let mut transfer = FakeTransfer::completing(Ok(vec![0x03, 0, 0, 0]));

        assert_eq!(
            wait_for_finger(&mut transfer, Duration::from_millis(30_000), None),
            Ok(vec![0x03, 0, 0, 0])
        );
        assert_eq!(transfer.cancel_calls, 0);
        assert_eq!(
            transfer.waits,
            [Duration::from_millis(CANCEL_POLL_MS)],
            "the wait blocks in short slices, not for the whole timeout"
        );
    }

    #[test]
    fn a_completion_after_one_empty_slice_is_not_cancelled() {
        let mut transfer = FakeTransfer::empty(1);
        transfer.completions.push_back(None);
        transfer
            .completions
            .push_back(Some(Ok(vec![0x03, 0, 0, 0])));

        assert_eq!(
            wait_for_finger(&mut transfer, Duration::from_millis(30_000), None),
            Ok(vec![0x03, 0, 0, 0])
        );
        assert_eq!(transfer.cancel_calls, 0, "no flag, no cancellation");
        assert_eq!(transfer.waits.len(), 2);
    }

    #[test]
    fn a_signal_before_the_wait_cancels_the_transfer_and_reaps_it() {
        let flag = SignalFlag::new();
        flag.raise(signal_hook::consts::signal::SIGINT);
        let mut transfer = FakeTransfer::empty(1);

        assert_eq!(
            wait_for_finger(&mut transfer, Duration::from_millis(30_000), Some(&flag)),
            Err(UsbError::Cancelled)
        );
        assert_eq!(transfer.cancel_calls, 1, "the transfer is cancelled once");
        assert_eq!(transfer.pending(), 0, "the cancelled completion was reaped");
    }

    #[test]
    fn a_signal_during_a_slice_cancels_after_that_slice_and_not_before() {
        let flag = SignalFlag::new();
        let mut transfer = FakeTransfer::empty(1);
        transfer.raise_on_wait = Some((1, flag.clone()));

        assert_eq!(
            wait_for_finger(&mut transfer, Duration::from_millis(30_000), Some(&flag)),
            Err(UsbError::Cancelled)
        );
        assert_eq!(
            transfer.waits[0],
            Duration::from_millis(CANCEL_POLL_MS),
            "the flag is polled at the slice boundary, not before the transfer"
        );
        assert_eq!(transfer.cancel_calls, 1);
        assert_eq!(transfer.pending(), 0);
    }

    #[test]
    fn no_completion_and_no_signal_is_a_timeout_that_still_reaps() {
        let mut transfer = FakeTransfer::empty(1);

        assert_eq!(
            wait_for_finger(&mut transfer, Duration::from_millis(1), None),
            Err(UsbError::Timeout)
        );
        assert_eq!(transfer.cancel_calls, 1);
        assert_eq!(transfer.pending(), 0, "the cancelled completion was reaped");
    }
}

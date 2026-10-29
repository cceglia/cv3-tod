//! The probe's blocking adapter over the shared command exchange.
//!
//! A command is written to bulk OUT; the sensor answers on interrupt IN with an eight-byte
//! announcement (`status: u32`, `reply_len: u32`, both little-endian); when `reply_len` is
//! non-zero the body follows on bulk IN. The sequence itself — including answering a
//! `CV_GET_HOST_TIMESTAMP_INTERRUPT` with vendor control request `0x0d` — lives in
//! [`cv3_wire::Exchange`], so the plugin runs exactly the same machine with asynchronous
//! `libfprint` transfers.
//!
//! The byte-level I/O is [`UsbIo`], which lets the sequencing be tested against a mock and keeps
//! the command transfers non-cancellable in the real transport. Only the finger wait has a
//! cancellation path, and it is not part of a command exchange.
//!
//! The body is read before `command` returns, so the next command can never start with an
//! announced body still in flight.

use std::time::Duration;

use cv3_core::proto::interrupt;
use cv3_wire::{FingerError, FingerWait, IoFailure, IoReply, Transfer, WireError};

pub use cv3_wire::{ANNOUNCEMENT_LEN, MAX_REPLY_LEN, Reply};

use crate::usb::UsbError;

/// Bytes in the finger event the interrupt endpoint delivers.
pub const FINGER_EVENT_LEN: usize = 4;

/// The byte-level USB operations the exchange needs.
pub trait UsbIo {
    /// Writes one command frame to bulk OUT.
    fn out(&mut self, frame: &[u8]) -> Result<(), UsbError>;

    /// Reads the announcement. Returns the bytes actually read, which may be short; the exchange
    /// rejects a short read rather than reading past it. A host timestamp request is returned as
    /// the sensor sent it: answering it is the exchange's job, not the transport's.
    fn read_interrupt(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbError>;

    /// Reads up to `len` bytes of an announced reply body from bulk IN.
    fn read_bulk(&mut self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError>;

    /// Reads one event from the interrupt endpoint, waiting at most `timeout`.
    ///
    /// This is the finger wait, and the only transfer the protocol allows to be cancelled: an
    /// implementation cancels it on timeout or on a shutdown request, and reaps the cancelled
    /// completion, so the interface stays usable. A command transfer must never take this path.
    fn read_finger(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbError>;

    /// Answers a `CV_GET_HOST_TIMESTAMP_INTERRUPT` with the packed host timestamp.
    ///
    /// This is a vendor device control request, not a bulk frame: it never appears in a transcript
    /// and never touches the command path. The exchange calls it when the sensor asks for the
    /// clock, during an announcement read.
    fn sync_timestamp(&mut self, packed: u32) -> Result<(), UsbError>;

    /// The timestamp syncs sent since the last call, for `--hex`.
    ///
    /// A transport that has no diagnostics returns nothing, which is the default.
    fn take_timestamps(&mut self) -> Vec<u32> {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeError {
    /// Writing the command failed.
    Out(UsbError),
    /// Reading the announcement failed.
    Interrupt(UsbError),
    /// Reading the announced body failed.
    Bulk(UsbError),
    /// Reading the finger event failed.
    Finger(UsbError),
    /// The interrupt read returned fewer than [`ANNOUNCEMENT_LEN`] bytes.
    ShortAnnouncement { got: usize },
    /// The finger event is shorter than [`FINGER_EVENT_LEN`].
    ShortFingerEvent { got: usize },
    /// The announcement declared a body larger than [`MAX_REPLY_LEN`].
    ReplyTooLarge { announced: usize, max: usize },
    /// The body read did not deliver exactly the announced number of bytes.
    BodyLength { announced: usize, got: usize },
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Out(error) => write!(f, "sending the command failed: {error}"),
            Self::Interrupt(error) => write!(f, "reading the reply announcement failed: {error}"),
            Self::Bulk(error) => write!(f, "reading the reply body failed: {error}"),
            Self::Finger(error) => write!(f, "reading the finger event failed: {error}"),
            Self::ShortAnnouncement { got } => write!(
                f,
                "reply announcement is {got} bytes, expected {ANNOUNCEMENT_LEN}"
            ),
            Self::ShortFingerEvent { got } => write!(
                f,
                "finger event is {got} bytes, expected at least {FINGER_EVENT_LEN}"
            ),
            Self::ReplyTooLarge { announced, max } => {
                write!(
                    f,
                    "reply announces {announced} bytes, more than the {max} allowed"
                )
            }
            Self::BodyLength { announced, got } => {
                write!(f, "reply announced {announced} bytes but delivered {got}")
            }
        }
    }
}

impl std::error::Error for ExchangeError {}

impl From<WireError> for ExchangeError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Out(failure) => Self::Out(usb_failure(failure)),
            WireError::Interrupt(failure) => Self::Interrupt(usb_failure(failure)),
            WireError::Bulk(failure) => Self::Bulk(usb_failure(failure)),
            // Before the sequencing moved here, a failed timestamp answer came out of
            // `read_interrupt`; keeping it on the announcement stage preserves that report.
            WireError::Control(failure) => Self::Interrupt(usb_failure(failure)),
            WireError::ShortAnnouncement { got } => Self::ShortAnnouncement { got },
            WireError::ReplyTooLarge { announced, max } => Self::ReplyTooLarge { announced, max },
            WireError::BodyLength { announced, got } => Self::BodyLength { announced, got },
            WireError::TooManyTimestampRequests => Self::Interrupt(UsbError::TimestampRequests),
        }
    }
}

fn io_failure(error: UsbError) -> IoFailure {
    match error {
        UsbError::Timeout => IoFailure::Timeout,
        UsbError::Disconnected => IoFailure::Disconnected,
        UsbError::Stall => IoFailure::Stall,
        UsbError::Cancelled => IoFailure::Cancelled,
        UsbError::Busy => IoFailure::Busy,
        other => IoFailure::Other(other.to_string()),
    }
}

fn usb_failure(failure: IoFailure) -> UsbError {
    match failure {
        IoFailure::Timeout => UsbError::Timeout,
        IoFailure::Disconnected => UsbError::Disconnected,
        IoFailure::Stall => UsbError::Stall,
        IoFailure::Cancelled => UsbError::Cancelled,
        IoFailure::Busy => UsbError::Busy,
        IoFailure::Other(message) => UsbError::Other(message),
    }
}

/// Sends one command and completes its announced reply.
pub struct Exchange<'a> {
    io: &'a mut dyn UsbIo,
}

impl<'a> Exchange<'a> {
    pub fn new(io: &'a mut dyn UsbIo) -> Self {
        Self { io }
    }

    /// Writes `frame`, waits for the announcement, and reads the body when one is announced.
    ///
    /// A failure is returned without reading a body; a caller must not send another command after
    /// an error, because the device may still hold unread reply bytes. The write timeout belongs to
    /// [`UsbIo::out`]; the announcement and body use the times on the transfers.
    pub fn command(&mut self, frame: &[u8]) -> Result<Reply, ExchangeError> {
        let mut exchange = cv3_wire::Exchange::new(frame.to_vec());
        while let Some(transfer) = exchange.next_transfer() {
            let result = self.perform(transfer);
            exchange.on_io_result(result);
        }
        exchange
            .outcome()
            .expect("a finished exchange reports an outcome")
            .map_err(ExchangeError::from)
    }

    fn perform(&mut self, transfer: Transfer) -> IoReply {
        match transfer {
            Transfer::Out { frame, .. } => match self.io.out(&frame) {
                Ok(()) => IoReply::Completed,
                Err(error) => IoReply::Failed(io_failure(error)),
            },
            Transfer::InterruptIn { timeout_ms, .. } => {
                match self
                    .io
                    .read_interrupt(Duration::from_millis(timeout_ms as u64))
                {
                    Ok(payload) => IoReply::Data(payload),
                    Err(error) => IoReply::Failed(io_failure(error)),
                }
            }
            Transfer::FingerIn { timeout_ms } => {
                match self
                    .io
                    .read_finger(Duration::from_millis(timeout_ms as u64))
                {
                    Ok(payload) => IoReply::Data(payload),
                    Err(error) => IoReply::Failed(io_failure(error)),
                }
            }
            Transfer::BulkIn { len, timeout_ms } => {
                match self
                    .io
                    .read_bulk(len, Duration::from_millis(timeout_ms as u64))
                {
                    Ok(body) => IoReply::Data(body),
                    Err(error) => IoReply::Failed(io_failure(error)),
                }
            }
            Transfer::ControlOut { value, index, .. } => {
                let packed = u32::from(value) | (u32::from(index) << 16);
                match self.io.sync_timestamp(packed) {
                    Ok(()) => IoReply::Completed,
                    Err(error) => IoReply::Failed(io_failure(error)),
                }
            }
        }
    }

    /// Waits for the finger event, the one transfer the protocol allows to be cancelled.
    ///
    /// Returns the event word from the first four bytes. The caller decides which values mean
    /// something; `0x03` is the sensor's "finger read". A host timestamp request is answered while
    /// waiting, exactly as during a reply announcement, and the interrupt endpoint is read again. A
    /// short read or a transport failure is a typed error, never a panic.
    pub fn wait_finger(&mut self) -> Result<u32, ExchangeError> {
        let mut wait = FingerWait::new();
        while let Some(transfer) = wait.next_transfer() {
            let result = self.perform(transfer);
            wait.on_io_result(result);
        }
        match wait
            .outcome()
            .expect("a finished finger wait reports an outcome")
        {
            Ok(()) => Ok(interrupt::FINGER),
            Err(FingerError::Interrupt(failure) | FingerError::Control(failure)) => {
                Err(ExchangeError::Finger(usb_failure(failure)))
            }
            Err(FingerError::TooManyTimestampRequests) => {
                Err(ExchangeError::Finger(UsbError::TimestampRequests))
            }
            Err(FingerError::ShortEvent { got }) => Err(ExchangeError::ShortFingerEvent { got }),
            // The probe reports the raw word; its transport turns an unexpected value into a typed
            // error with the same wording the plugin uses.
            Err(FingerError::UnexpectedEvent { event }) => Ok(event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp;
    use cv3_core::proto::timeout;
    use std::cell::RefCell;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Out(Vec<u8>),
        Interrupt(Duration),
        Bulk(usize, Duration),
        Finger(Duration),
        Timestamp(u32),
    }

    struct MockIo {
        interrupt: Result<Vec<u8>, UsbError>,
        /// When non-empty, consumed before `interrupt`, so one exchange can see several reads.
        interrupt_queue: std::collections::VecDeque<Result<Vec<u8>, UsbError>>,
        bulk: Result<Vec<u8>, UsbError>,
        finger: Result<Vec<u8>, UsbError>,
        /// When non-empty, consumed before `finger`, so one wait can see several reads.
        finger_queue: std::collections::VecDeque<Result<Vec<u8>, UsbError>>,
        out_error: Option<UsbError>,
        sync_error: Option<UsbError>,
        timestamps: Vec<u32>,
        calls: RefCell<Vec<Call>>,
    }

    impl MockIo {
        fn new(status: u32, reply_len: u32) -> Self {
            let mut announcement = [0u8; ANNOUNCEMENT_LEN];
            announcement[..4].copy_from_slice(&status.to_le_bytes());
            announcement[4..].copy_from_slice(&reply_len.to_le_bytes());
            Self {
                interrupt: Ok(announcement.to_vec()),
                interrupt_queue: std::collections::VecDeque::new(),
                bulk: Ok(vec![0xAA; reply_len as usize]),
                finger: Ok(0x03u32.to_le_bytes().to_vec()),
                finger_queue: std::collections::VecDeque::new(),
                out_error: None,
                sync_error: None,
                timestamps: Vec::new(),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    impl UsbIo for MockIo {
        fn out(&mut self, frame: &[u8]) -> Result<(), UsbError> {
            self.calls.borrow_mut().push(Call::Out(frame.to_vec()));
            match &self.out_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn read_interrupt(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.calls.borrow_mut().push(Call::Interrupt(timeout));
            match self.interrupt_queue.pop_front() {
                Some(next) => next,
                None => self.interrupt.clone(),
            }
        }

        fn read_bulk(&mut self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.calls.borrow_mut().push(Call::Bulk(len, timeout));
            self.bulk.clone()
        }

        fn read_finger(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.calls.borrow_mut().push(Call::Finger(timeout));
            match self.finger_queue.pop_front() {
                Some(next) => next,
                None => self.finger.clone(),
            }
        }

        fn sync_timestamp(&mut self, packed: u32) -> Result<(), UsbError> {
            self.calls.borrow_mut().push(Call::Timestamp(packed));
            match &self.sync_error {
                Some(error) => Err(error.clone()),
                None => {
                    self.timestamps.push(packed);
                    Ok(())
                }
            }
        }

        fn take_timestamps(&mut self) -> Vec<u32> {
            std::mem::take(&mut self.timestamps)
        }
    }

    #[test]
    fn a_timestamp_sync_is_a_recorded_host_control_call() {
        let mut io = MockIo::new(0, 0);

        assert_eq!(io.sync_timestamp(0x1234_5678), Ok(()));
        assert_eq!(io.calls(), [Call::Timestamp(0x1234_5678)]);
        assert_eq!(io.take_timestamps(), [0x1234_5678]);
        assert_eq!(io.take_timestamps(), [], "the log is drained");
    }

    #[test]
    fn a_non_zero_announcement_reads_exactly_its_body() {
        let mut io = MockIo::new(0x0000_0003, 5);
        io.bulk = Ok(vec![1, 2, 3, 4, 5]);
        let mut exchange = Exchange::new(&mut io);

        let reply = exchange.command(&[0x23, 0x00]).expect("reply completes");

        assert_eq!(reply.status, 3, "announcement status is passed through");
        assert_eq!(reply.body, [1, 2, 3, 4, 5]);
        assert_eq!(
            io.calls(),
            [
                Call::Out(vec![0x23, 0x00]),
                Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64)),
                Call::Bulk(5, Duration::from_millis(timeout::REPLY_MS as u64)),
            ]
        );
    }

    #[test]
    fn a_zero_length_announcement_performs_no_bulk_read() {
        let mut io = MockIo::new(0x0000_0002, 0);
        let mut exchange = Exchange::new(&mut io);

        let reply = exchange
            .command(&[0x04, 0x00])
            .expect("empty reply completes");

        assert_eq!(
            reply,
            Reply {
                status: 2,
                body: Vec::new()
            }
        );
        assert_eq!(
            io.calls(),
            [
                Call::Out(vec![0x04, 0x00]),
                Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64)),
            ]
        );
    }

    #[test]
    fn a_short_announcement_is_a_typed_error_and_reads_no_body() {
        let mut io = MockIo::new(0, 16);
        io.interrupt = Ok(vec![0; ANNOUNCEMENT_LEN - 1]);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x23]),
            Err(ExchangeError::ShortAnnouncement {
                got: ANNOUNCEMENT_LEN - 1
            })
        );
        assert_eq!(io.calls().len(), 2, "only the write and the short read");
    }

    #[test]
    fn an_absurd_announced_length_is_refused_without_a_read() {
        let mut io = MockIo::new(0, (MAX_REPLY_LEN + 1) as u32);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x73]),
            Err(ExchangeError::ReplyTooLarge {
                announced: MAX_REPLY_LEN + 1,
                max: MAX_REPLY_LEN,
            })
        );
        assert_eq!(io.calls().len(), 2);
    }

    #[test]
    fn a_write_error_is_typed_and_stops_the_exchange() {
        let mut io = MockIo::new(0, 0);
        io.out_error = Some(UsbError::Timeout);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x23]),
            Err(ExchangeError::Out(UsbError::Timeout))
        );
        assert_eq!(io.calls(), [Call::Out(vec![0x23])]);
    }

    #[test]
    fn an_announcement_error_is_typed_and_reads_no_body() {
        let mut io = MockIo::new(0, 16);
        io.interrupt = Err(UsbError::Disconnected);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x23]),
            Err(ExchangeError::Interrupt(UsbError::Disconnected))
        );
        assert_eq!(io.calls().len(), 2);
    }

    #[test]
    fn a_body_error_is_typed() {
        let mut io = MockIo::new(0, 4);
        io.bulk = Err(UsbError::Stall);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x23]),
            Err(ExchangeError::Bulk(UsbError::Stall))
        );
    }

    #[test]
    fn a_short_body_is_a_typed_error() {
        let mut io = MockIo::new(0, 8);
        io.bulk = Ok(vec![0; 4]);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.command(&[0x23]),
            Err(ExchangeError::BodyLength {
                announced: 8,
                got: 4
            })
        );
    }

    #[test]
    fn one_body_completes_before_the_next_command_starts() {
        let mut io = MockIo::new(0, 4);
        io.bulk = Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        Exchange::new(&mut io)
            .command(&[0x01])
            .expect("first reply completes");
        io.interrupt = Ok(vec![0; ANNOUNCEMENT_LEN]);
        Exchange::new(&mut io)
            .command(&[0x02])
            .expect("second reply completes");

        let calls = io.calls();
        assert_eq!(
            calls,
            [
                Call::Out(vec![0x01]),
                Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64)),
                Call::Bulk(4, Duration::from_millis(timeout::REPLY_MS as u64)),
                Call::Out(vec![0x02]),
                Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64)),
            ]
        );
    }

    #[test]
    fn a_host_timestamp_request_is_answered_through_the_shared_exchange() {
        // The sensor asks for the clock before announcing the reply. The shared machine answers it
        // with the control request and reads the interrupt endpoint again.
        let mut io = MockIo::new(0x0000_0002, 0);
        let mut announcement = vec![0u8; ANNOUNCEMENT_LEN];
        announcement[..4].copy_from_slice(&2u32.to_le_bytes());
        io.interrupt_queue
            .push_back(Ok(timestamp::HOST_TIMESTAMP_INTERRUPT
                .to_le_bytes()
                .to_vec()));
        io.interrupt_queue.push_back(Ok(announcement));
        let mut exchange = Exchange::new(&mut io);

        let reply = exchange.command(&[0x23]).expect("the announcement arrives");

        assert_eq!(reply.status, 2);
        let calls = io.calls();
        assert_eq!(calls[0], Call::Out(vec![0x23]));
        assert_eq!(
            calls[1],
            Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64))
        );
        assert!(
            matches!(calls[2], Call::Timestamp(_)),
            "the request is answered with the vendor control: {calls:?}"
        );
        assert_eq!(
            calls[3],
            Call::Interrupt(Duration::from_millis(timeout::REPLY_MS as u64))
        );
        assert_eq!(calls.len(), 4);
    }

    #[test]
    fn a_finger_wait_reads_the_interrupt_endpoint_with_the_finger_timeout() {
        let mut io = MockIo::new(0, 0);
        io.finger = Ok(0x03u32.to_le_bytes().to_vec());
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(exchange.wait_finger(), Ok(0x03));
        assert_eq!(
            io.calls(),
            [Call::Finger(Duration::from_millis(
                timeout::FINGER_MS as u64
            ))]
        );
    }

    #[test]
    fn a_short_finger_event_is_a_typed_error() {
        let mut io = MockIo::new(0, 0);
        io.finger = Ok(vec![0x03, 0x00, 0x00]);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.wait_finger(),
            Err(ExchangeError::ShortFingerEvent {
                got: FINGER_EVENT_LEN - 1
            })
        );
    }

    #[test]
    fn a_finger_timeout_is_typed_and_does_not_touch_the_command_path() {
        let mut io = MockIo::new(0, 0);
        io.finger = Err(UsbError::Timeout);
        let mut exchange = Exchange::new(&mut io);

        assert_eq!(
            exchange.wait_finger(),
            Err(ExchangeError::Finger(UsbError::Timeout))
        );
        assert_eq!(
            io.calls(),
            [Call::Finger(Duration::from_millis(
                timeout::FINGER_MS as u64
            ))]
        );
    }

    #[test]
    fn a_timestamp_request_during_the_finger_wait_is_answered_and_the_read_retried() {
        let mut io = MockIo::new(0, 0);
        io.finger = Ok(0x03u32.to_le_bytes().to_vec());
        io.finger_queue
            .push_back(Ok(cv3_wire::timestamp::HOST_TIMESTAMP_INTERRUPT
                .to_le_bytes()
                .to_vec()));
        {
            let mut exchange = Exchange::new(&mut io);
            assert_eq!(exchange.wait_finger(), Ok(0x03));
        }

        let calls = io.calls();
        assert!(
            matches!(
                calls[0],
                Call::Finger(duration)
                    if duration == Duration::from_millis(timeout::FINGER_MS as u64)
            ),
            "{calls:?}"
        );
        assert!(matches!(calls[1], Call::Timestamp(_)), "{calls:?}");
        assert!(matches!(calls[2], Call::Finger(_)), "{calls:?}");
    }

    #[test]
    fn a_command_never_waits_for_a_finger_event() {
        let mut io = MockIo::new(0, 2);
        let mut exchange = Exchange::new(&mut io);

        exchange.command(&[0x23]).expect("reply completes");

        assert!(
            !io.calls()
                .iter()
                .any(|call| matches!(call, Call::Finger(_))),
            "only the finger wait may take the finger path"
        );
    }
}

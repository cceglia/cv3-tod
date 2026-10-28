//! The out / interrupt / bulk-in exchange every command uses.
//!
//! A command is written to bulk OUT; the sensor answers on interrupt IN with an eight-byte
//! announcement (`status: u32`, `reply_len: u32`, both little-endian); when `reply_len` is
//! non-zero the body follows on bulk IN. The body is read before `command` returns, so the next
//! command can never start with an announced body still in flight.
//!
//! The byte-level I/O is [`UsbIo`], which lets the sequencing be tested against a mock and keeps
//! the command transfers non-cancellable in the real transport. Only the finger wait has a
//! cancellation path, and it is not part of a command exchange.

use std::time::Duration;

use cv3_core::proto::timeout;

use crate::usb::UsbError;

/// Bytes in the interrupt announcement.
pub const ANNOUNCEMENT_LEN: usize = 8;
/// Bytes in the finger event the interrupt endpoint delivers.
pub const FINGER_EVENT_LEN: usize = 4;

/// Largest body accepted. The audited implementation reads into an 8192-byte buffer; a length
/// beyond it cannot be a genuine reply and is refused rather than trusted.
pub const MAX_REPLY_LEN: usize = 8192;

/// The byte-level USB operations the exchange needs.
pub trait UsbIo {
    /// Writes one command frame to bulk OUT.
    fn out(&mut self, frame: &[u8]) -> Result<(), UsbError>;

    /// Reads the announcement. Returns the bytes actually read, which may be short; the exchange
    /// rejects a short read rather than reading past it.
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
    /// and never touches the command path. The real transport calls it from its interrupt
    /// demultiplexing and once at session start.
    fn sync_timestamp(&mut self, packed: u32) -> Result<(), UsbError>;

    /// The timestamp syncs sent since the last call, for `--hex`.
    ///
    /// A transport that has no diagnostics returns nothing, which is the default.
    fn take_timestamps(&mut self) -> Vec<u32> {
        Vec::new()
    }
}

/// What the sensor announced and, if it announced one, the body that followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The announcement's status word. The command's own status is at offset 20 of `body` and is
    /// interpreted by the core, not here; an empty announcement has no such frame.
    pub status: u32,
    pub body: Vec<u8>,
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
    /// an error, because the device may still hold unread reply bytes.
    pub fn command(&mut self, frame: &[u8]) -> Result<Reply, ExchangeError> {
        self.io.out(frame).map_err(ExchangeError::Out)?;

        let announcement = self
            .io
            .read_interrupt(Duration::from_millis(timeout::REPLY_MS as u64))
            .map_err(ExchangeError::Interrupt)?;
        if announcement.len() < ANNOUNCEMENT_LEN {
            return Err(ExchangeError::ShortAnnouncement {
                got: announcement.len(),
            });
        }

        let status = le32(&announcement, 0);
        let announced = le32(&announcement, 4) as usize;
        if announced == 0 {
            return Ok(Reply {
                status,
                body: Vec::new(),
            });
        }
        if announced > MAX_REPLY_LEN {
            return Err(ExchangeError::ReplyTooLarge {
                announced,
                max: MAX_REPLY_LEN,
            });
        }

        let body = self
            .io
            .read_bulk(announced, Duration::from_millis(timeout::REPLY_MS as u64))
            .map_err(ExchangeError::Bulk)?;
        if body.len() != announced {
            return Err(ExchangeError::BodyLength {
                announced,
                got: body.len(),
            });
        }

        Ok(Reply { status, body })
    }

    /// Waits for the finger event, the one transfer the protocol allows to be cancelled.
    ///
    /// Returns the event word from the first four bytes. The caller decides which values mean
    /// something; `0x03` is the sensor's "finger read". A short read or a transport failure is a
    /// typed error, never a panic.
    pub fn wait_finger(&mut self) -> Result<u32, ExchangeError> {
        let event = self
            .io
            .read_finger(Duration::from_millis(timeout::FINGER_MS as u64))
            .map_err(ExchangeError::Finger)?;
        if event.len() < FINGER_EVENT_LEN {
            return Err(ExchangeError::ShortFingerEvent { got: event.len() });
        }
        Ok(le32(&event, 0))
    }
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
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
        bulk: Result<Vec<u8>, UsbError>,
        finger: Result<Vec<u8>, UsbError>,
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
                bulk: Ok(vec![0xAA; reply_len as usize]),
                finger: Ok(0x03u32.to_le_bytes().to_vec()),
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
            self.interrupt.clone()
        }

        fn read_bulk(&mut self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.calls.borrow_mut().push(Call::Bulk(len, timeout));
            self.bulk.clone()
        }

        fn read_finger(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.calls.borrow_mut().push(Call::Finger(timeout));
            self.finger.clone()
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

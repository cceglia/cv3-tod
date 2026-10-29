//! The one I/O-free home for the sensor's command exchange.
//!
//! Every command the driver sends follows the same shape: the frame goes out on bulk OUT, the sensor
//! announces the reply on interrupt IN with an eight-byte `(status, length)` pair, and when the
//! announced length is non-zero the body follows on bulk IN. An interrupt payload whose first word
//! is `5` is not an announcement at all but the sensor asking for the host timestamp, which the host
//! answers with vendor control request `0x0d` and then reads the interrupt endpoint again.
//!
//! [`Exchange`] owns that sequence as a small step machine: [`Exchange::next_transfer`] says what to
//! perform, [`Exchange::on_io_result`] consumes what happened, and the machine finishes with a
//! [`Reply`] or a typed [`WireError`]. It performs no I/O and knows nothing about USB beyond the
//! endpoint numbers, which are protocol constants from [`cv3_core::proto::endpoint`]. That is what
//! lets the probe's blocking transport and the plugin's `libfprint` transport share one
//! implementation instead of two copies of the same offsets.
//!
//! Accepted body lengths and the parsed values come from [`Reply`]; the core still validates the
//! frame itself, so a body that is too short survives this layer with its announcement status and is
//! rejected by the operation that asked for it.

#![forbid(unsafe_code)]

pub mod timestamp;

use std::fmt;

use cv3_core::event::{Event, TransportError};
use cv3_core::frame::Header;
use cv3_core::proto::{cmd, endpoint, timeout};

use crate::timestamp::{MAX_REQUESTS, is_host_timestamp_request, pack};

/// Bytes in the interrupt announcement.
pub const ANNOUNCEMENT_LEN: usize = 8;
/// Largest body accepted. The audited implementation reads into an 8192-byte buffer; a length
/// beyond it cannot be a genuine reply and is refused rather than trusted.
pub const MAX_REPLY_LEN: usize = 8192;
/// Buffer size an IN transfer for the interrupt endpoint is offered. An announcement is eight bytes
/// and a timestamp request four; the extra room is for an endpoint whose packet size is larger.
pub const INTERRUPT_BUFFER_LEN: usize = 64;

/// One USB transfer the exchange wants performed.
///
/// A `Vec` in a transfer is owned by the caller for the length of the transfer. The plugin hands it
/// to `libfprint` with a NULL free function and keeps it alive until it reports the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transfer {
    /// Write the frame to the command (bulk OUT) endpoint.
    Out { frame: Vec<u8>, timeout_ms: u32 },
    /// Read one interrupt payload of at most `max_len` bytes.
    InterruptIn { max_len: usize, timeout_ms: u32 },
    /// Read exactly the announced number of bytes from the reply (bulk IN) endpoint.
    BulkIn { len: usize, timeout_ms: u32 },
    /// Answer the host timestamp request: a vendor/device OUT control request with no data stage.
    ControlOut {
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        timeout_ms: u32,
    },
}

impl Transfer {
    /// The endpoint this transfer addresses, as the protocol numbers it.
    pub fn endpoint(&self) -> u8 {
        match self {
            Self::Out { .. } => endpoint::OUT,
            Self::InterruptIn { .. } | Self::ControlOut { .. } => endpoint::INTERRUPT,
            Self::BulkIn { .. } => endpoint::IN,
        }
    }
}

/// What the transport reports for one transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoReply {
    /// An OUT or control transfer completed.
    Completed,
    /// An IN transfer completed with the bytes it delivered. The length may be short; the exchange
    /// checks it against what it asked for.
    Data(Vec<u8>),
    /// The transfer failed. The exchange turns this into a typed [`WireError`]; the stage names
    /// which transfer failed.
    Failed(IoFailure),
}

/// A transport failure, classified by what the caller can do about it.
///
/// This is the wire layer's own type: the probe maps its USB error onto it and the plugin maps
/// `libfprint`'s `GError` onto it, so neither transport type reaches the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoFailure {
    /// A transfer did not complete in its window.
    Timeout,
    /// The sensor left the bus.
    Disconnected,
    /// An endpoint stalled.
    Stall,
    /// The transfer was cancelled. A command transfer never is; only a finger wait may be.
    Cancelled,
    /// The device or its interface is held by another process.
    Busy,
    /// Anything else, with the transport's own description.
    Other(String),
}

impl fmt::Display for IoFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("transfer timed out"),
            Self::Disconnected => f.write_str("sensor disconnected"),
            Self::Stall => f.write_str("endpoint stalled"),
            Self::Cancelled => f.write_str("transfer cancelled"),
            Self::Busy => f.write_str("sensor is busy"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for IoFailure {}

/// What the sensor announced and, if it announced one, the body that followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The announcement's status word. The command's own status is at offset 20 of `body` and is
    /// interpreted by the core, not here; an empty announcement has no such frame.
    pub status: u32,
    pub body: Vec<u8>,
}

/// Why one command exchange did not produce a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Writing the command failed.
    Out(IoFailure),
    /// Reading the announcement failed.
    Interrupt(IoFailure),
    /// Reading the announced body failed.
    Bulk(IoFailure),
    /// Answering the host timestamp request failed.
    Control(IoFailure),
    /// The interrupt read returned fewer than [`ANNOUNCEMENT_LEN`] bytes.
    ShortAnnouncement { got: usize },
    /// The announcement declared a body larger than [`MAX_REPLY_LEN`].
    ReplyTooLarge { announced: usize, max: usize },
    /// The body read did not deliver exactly the announced number of bytes.
    BodyLength { announced: usize, got: usize },
    /// The sensor asked for the host timestamp more times than one exchange answers.
    TooManyTimestampRequests,
}

impl WireError {
    /// Whether the exchange ended because someone asked it to stop.
    pub fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::Out(IoFailure::Cancelled)
                | Self::Interrupt(IoFailure::Cancelled)
                | Self::Bulk(IoFailure::Cancelled)
                | Self::Control(IoFailure::Cancelled)
        )
    }

    /// Maps the failure onto the core's own transport error, naming the transfer that failed.
    ///
    /// A timeout is deliberately distinguishable by its text: a sensor that refuses the bulk OUT
    /// and one that accepts it but never announces a reply need different next steps.
    pub fn to_transport_error(&self) -> TransportError {
        fn stage(transfer: &str, failure: &IoFailure) -> TransportError {
            match failure {
                IoFailure::Disconnected => TransportError::Disconnected,
                IoFailure::Stall => TransportError::Stall,
                IoFailure::Cancelled => TransportError::Other("transfer cancelled".to_owned()),
                IoFailure::Busy => TransportError::Other("the sensor is busy".to_owned()),
                IoFailure::Other(message) => TransportError::Other(message.clone()),
                IoFailure::Timeout => TransportError::Other(format!("{transfer} timed out")),
            }
        }

        match self {
            Self::Out(failure) => stage("sending the command", failure),
            Self::Interrupt(failure) => stage("waiting for the reply announcement", failure),
            Self::Bulk(failure) => stage("reading the reply body", failure),
            Self::Control(failure) => stage("answering the host timestamp request", failure),
            Self::ShortAnnouncement { got } => TransportError::Other(format!(
                "reply announcement is {got} bytes, expected {ANNOUNCEMENT_LEN}"
            )),
            Self::ReplyTooLarge { announced, max } => TransportError::Other(format!(
                "reply announces {announced} bytes, more than the {max} allowed"
            )),
            Self::BodyLength { announced, got } => TransportError::Other(format!(
                "reply announced {announced} bytes but delivered {got}"
            )),
            Self::TooManyTimestampRequests => TransportError::Other(
                "sensor kept requesting the host timestamp without a reply".to_owned(),
            ),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Out(error) => write!(f, "sending the command failed: {error}"),
            Self::Interrupt(error) => write!(f, "reading the reply announcement failed: {error}"),
            Self::Bulk(error) => write!(f, "reading the reply body failed: {error}"),
            Self::Control(error) => {
                write!(f, "answering the host timestamp request failed: {error}")
            }
            Self::ShortAnnouncement { got } => write!(
                f,
                "reply announcement is {got} bytes, expected {ANNOUNCEMENT_LEN}"
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
            Self::TooManyTimestampRequests => {
                f.write_str("sensor kept requesting the host timestamp without a reply")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// Turns one finished exchange into the event the core operation expects.
///
/// A body that is too short to carry a header still reaches the core, with status zero: the core
/// validates the frame first, so it reports the malformed body rather than trusting a status that
/// was never on the wire. A cancelled exchange is a cancellation event, not a transport error, so
/// an operation tears down and reports it as one.
pub fn event_from_outcome(outcome: Result<Reply, WireError>) -> Event {
    match outcome {
        Ok(reply) if reply.body.is_empty() => Event::ReplyWithoutBody,
        Ok(reply) => {
            let status = Header::parse(&reply.body).map_or(0, |header| header.status);
            Event::Reply {
                status,
                body: reply.body,
            }
        }
        Err(error) if error.is_cancelled() => Event::Cancelled,
        Err(error) => Event::Transport(error.to_transport_error()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Out {
        frame: Vec<u8>,
        timeout_ms: u32,
    },
    /// `answered` is how many timestamp requests this exchange has already answered.
    Interrupt {
        answered: usize,
    },
    Bulk {
        announced: usize,
        status: u32,
    },
    Control {
        packed: u32,
        answered: usize,
    },
    Done(Result<Reply, WireError>),
}

/// One command: write it, announce it, read the body, answering timestamp requests on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    state: State,
}

impl Exchange {
    /// Builds the exchange for one command frame.
    ///
    /// The write timeout is chosen from the command: teardown frames (`0x04` close and `0x68`
    /// cancel) get the shorter teardown window, everything else the generous command window. Both,
    /// and every reply timeout, are the core's protocol constants; a command transfer is never
    /// cancelled, because aborting one mid-flight deep-wedges this sensor.
    pub fn new(frame: Vec<u8>) -> Self {
        let timeout_ms = out_timeout(&frame);
        Self {
            state: State::Out { frame, timeout_ms },
        }
    }

    /// The transfer to perform next, or `None` once the exchange has finished.
    ///
    /// Calling it again before [`Self::on_io_result`] returns the same transfer: the machine never
    /// silently skips a step.
    pub fn next_transfer(&mut self) -> Option<Transfer> {
        match &self.state {
            State::Out { frame, timeout_ms } => Some(Transfer::Out {
                frame: frame.clone(),
                timeout_ms: *timeout_ms,
            }),
            State::Interrupt { .. } => Some(Transfer::InterruptIn {
                max_len: INTERRUPT_BUFFER_LEN,
                timeout_ms: timeout::REPLY_MS,
            }),
            State::Bulk { announced, .. } => Some(Transfer::BulkIn {
                len: *announced,
                timeout_ms: timeout::REPLY_MS,
            }),
            State::Control { packed, .. } => Some(Transfer::ControlOut {
                request_type: timestamp::HOST_TIMESTAMP_REQUEST_TYPE,
                request: timestamp::HOST_TIMESTAMP_REQUEST,
                value: *packed as u16,
                index: (*packed >> 16) as u16,
                timeout_ms: timestamp::SYNC_TIMEOUT_MS,
            }),
            State::Done(_) => None,
        }
    }

    /// Consumes the result of the transfer [`Self::next_transfer`] returned.
    ///
    /// A result that does not match the pending step is treated as a transport failure of that
    /// step, never as data to trust.
    pub fn on_io_result(&mut self, reply: IoReply) {
        let state = std::mem::replace(&mut self.state, State::Done(Ok(Reply::empty())));
        self.state = match state {
            State::Out { .. } => match reply {
                IoReply::Completed | IoReply::Data(_) => State::Interrupt { answered: 0 },
                IoReply::Failed(failure) => State::Done(Err(WireError::Out(failure))),
            },

            State::Interrupt { answered } => match reply {
                IoReply::Data(payload) => on_announcement(answered, payload),
                IoReply::Completed => State::Done(Err(WireError::ShortAnnouncement { got: 0 })),
                IoReply::Failed(failure) => State::Done(Err(WireError::Interrupt(failure))),
            },

            State::Bulk { announced, status } => match reply {
                IoReply::Data(body) if body.len() == announced => {
                    State::Done(Ok(Reply { status, body }))
                }
                IoReply::Data(body) => State::Done(Err(WireError::BodyLength {
                    announced,
                    got: body.len(),
                })),
                IoReply::Completed => State::Done(Err(WireError::BodyLength { announced, got: 0 })),
                IoReply::Failed(failure) => State::Done(Err(WireError::Bulk(failure))),
            },

            State::Control { answered, .. } => match reply {
                // The answer was accepted; read the interrupt endpoint again with the same count,
                // so a sensor that keeps asking is still bounded.
                IoReply::Completed | IoReply::Data(_) => State::Interrupt { answered },
                IoReply::Failed(failure) => State::Done(Err(WireError::Control(failure))),
            },

            done @ State::Done(_) => done,
        };
    }

    /// The finished outcome, or `None` while a transfer is still pending.
    pub fn outcome(&self) -> Option<Result<Reply, WireError>> {
        match &self.state {
            State::Done(result) => Some(result.clone()),
            _ => None,
        }
    }
}

fn on_announcement(answered: usize, payload: Vec<u8>) -> State {
    if is_host_timestamp_request(&payload) {
        if answered >= MAX_REQUESTS {
            return State::Done(Err(WireError::TooManyTimestampRequests));
        }
        return State::Control {
            packed: pack(std::time::SystemTime::now()),
            answered: answered + 1,
        };
    }
    if payload.len() < ANNOUNCEMENT_LEN {
        return State::Done(Err(WireError::ShortAnnouncement { got: payload.len() }));
    }
    let status = le32(&payload, 0);
    let announced = le32(&payload, 4) as usize;
    if announced == 0 {
        return State::Done(Ok(Reply {
            status,
            body: Vec::new(),
        }));
    }
    if announced > MAX_REPLY_LEN {
        return State::Done(Err(WireError::ReplyTooLarge {
            announced,
            max: MAX_REPLY_LEN,
        }));
    }
    State::Bulk { announced, status }
}

impl Reply {
    fn empty() -> Self {
        Self {
            status: 0,
            body: Vec::new(),
        }
    }
}

fn out_timeout(frame: &[u8]) -> u32 {
    match Header::parse(frame) {
        Ok(header) if header.cmd == cmd::CLOSE_SESSION || header.cmd == cmd::CANCEL_CAPTURE => {
            timeout::TEARDOWN_MS
        }
        _ => timeout::COMMAND_MS,
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
    use cv3_core::frame;
    use cv3_core::proto::{attr, timeout};

    /// A frame whose command is `cmd`, long enough for the writer to pick its timeout.
    fn command(cmd: u16) -> Vec<u8> {
        frame::build_plain(cmd, attr::SESSION, 0, &[])
    }

    fn announcement(status: u32, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; ANNOUNCEMENT_LEN];
        bytes[..4].copy_from_slice(&status.to_le_bytes());
        bytes[4..].copy_from_slice(&(len as u32).to_le_bytes());
        bytes
    }

    /// Drives an exchange with scripted transport results, returning the outcome and every transfer
    /// the machine asked for.
    fn drive(
        mut exchange: Exchange,
        mut results: impl Iterator<Item = IoReply>,
    ) -> (Option<Result<Reply, WireError>>, Vec<Transfer>) {
        let mut transfers = Vec::new();
        while let Some(transfer) = exchange.next_transfer() {
            transfers.push(transfer);
            match results.next() {
                Some(result) => exchange.on_io_result(result),
                None => panic!("the script ran out of results"),
            }
        }
        (exchange.outcome(), transfers)
    }

    #[test]
    fn a_positive_announcement_reads_exactly_its_body() {
        let (outcome, transfers) = drive(
            Exchange::new(command(cmd::CHALLENGE)),
            [
                IoReply::Completed,
                IoReply::Data(announcement(3, 5)),
                IoReply::Data(vec![1, 2, 3, 4, 5]),
            ]
            .into_iter(),
        );

        assert_eq!(
            outcome,
            Some(Ok(Reply {
                status: 3,
                body: vec![1, 2, 3, 4, 5],
            }))
        );
        assert_eq!(
            transfers,
            [
                Transfer::Out {
                    frame: command(cmd::CHALLENGE),
                    timeout_ms: timeout::COMMAND_MS,
                },
                Transfer::InterruptIn {
                    max_len: INTERRUPT_BUFFER_LEN,
                    timeout_ms: timeout::REPLY_MS,
                },
                Transfer::BulkIn {
                    len: 5,
                    timeout_ms: timeout::REPLY_MS,
                },
            ]
        );
    }

    #[test]
    fn a_zero_length_announcement_performs_no_bulk_read() {
        let (outcome, transfers) = drive(
            Exchange::new(command(cmd::CLOSE_SESSION)),
            [IoReply::Completed, IoReply::Data(announcement(2, 0))].into_iter(),
        );

        assert_eq!(
            outcome,
            Some(Ok(Reply {
                status: 2,
                body: Vec::new(),
            }))
        );
        assert_eq!(transfers.len(), 2, "no body transfer");
        assert!(matches!(transfers[1], Transfer::InterruptIn { .. }));
    }

    #[test]
    fn the_announced_length_is_what_the_body_read_requests() {
        let (outcome, transfers) = drive(
            Exchange::new(command(cmd::CHALLENGE)),
            [
                IoReply::Completed,
                IoReply::Data(announcement(0, 192)),
                IoReply::Data(vec![0; 192]),
            ]
            .into_iter(),
        );

        assert!(outcome.is_some_and(|result| result.is_ok()));
        assert_eq!(
            transfers[2],
            Transfer::BulkIn {
                len: 192,
                timeout_ms: timeout::REPLY_MS,
            }
        );
    }

    #[test]
    fn a_short_announcement_is_a_typed_error_and_reads_no_body() {
        let (outcome, transfers) = drive(
            Exchange::new(command(cmd::CHALLENGE)),
            [
                IoReply::Completed,
                IoReply::Data(vec![0; ANNOUNCEMENT_LEN - 1]),
            ]
            .into_iter(),
        );

        assert_eq!(
            outcome,
            Some(Err(WireError::ShortAnnouncement {
                got: ANNOUNCEMENT_LEN - 1,
            }))
        );
        assert_eq!(transfers.len(), 2, "only the write and the short read");
    }

    #[test]
    fn an_absurd_announced_length_is_refused_without_a_read() {
        let (outcome, transfers) = drive(
            Exchange::new(command(cmd::VERIFY)),
            [
                IoReply::Completed,
                IoReply::Data(announcement(0, MAX_REPLY_LEN + 1)),
            ]
            .into_iter(),
        );

        assert_eq!(
            outcome,
            Some(Err(WireError::ReplyTooLarge {
                announced: MAX_REPLY_LEN + 1,
                max: MAX_REPLY_LEN,
            }))
        );
        assert_eq!(transfers.len(), 2);
    }

    #[test]
    fn a_short_body_is_a_typed_error() {
        let (outcome, _) = drive(
            Exchange::new(command(cmd::CHALLENGE)),
            [
                IoReply::Completed,
                IoReply::Data(announcement(0, 8)),
                IoReply::Data(vec![0; 4]),
            ]
            .into_iter(),
        );

        assert_eq!(
            outcome,
            Some(Err(WireError::BodyLength {
                announced: 8,
                got: 4,
            }))
        );
    }

    #[test]
    fn a_failure_at_each_stage_keeps_its_stage() {
        let cases = [
            (
                vec![IoReply::Failed(IoFailure::Timeout)],
                WireError::Out(IoFailure::Timeout),
            ),
            (
                vec![IoReply::Completed, IoReply::Failed(IoFailure::Timeout)],
                WireError::Interrupt(IoFailure::Timeout),
            ),
            (
                vec![
                    IoReply::Completed,
                    IoReply::Data(announcement(0, 4)),
                    IoReply::Failed(IoFailure::Disconnected),
                ],
                WireError::Bulk(IoFailure::Disconnected),
            ),
        ];

        for (results, expected) in cases {
            let (outcome, _) = drive(Exchange::new(command(cmd::CHALLENGE)), results.into_iter());
            assert_eq!(outcome, Some(Err(expected)));
        }
    }

    #[test]
    fn close_and_cancel_frames_use_the_teardown_timeout_and_others_the_command_timeout() {
        for cmd in [cmd::CLOSE_SESSION, cmd::CANCEL_CAPTURE] {
            let mut exchange = Exchange::new(command(cmd));
            assert!(matches!(
                exchange.next_transfer(),
                Some(Transfer::Out {
                    timeout_ms: timeout::TEARDOWN_MS,
                    ..
                })
            ));
        }

        for cmd in [
            cmd::CHALLENGE,
            cmd::CHALLENGE_RESPONSE,
            cmd::OPEN_SESSION,
            cmd::ARM_CAPTURE,
        ] {
            let mut exchange = Exchange::new(command(cmd));
            assert!(matches!(
                exchange.next_transfer(),
                Some(Transfer::Out {
                    timeout_ms: timeout::COMMAND_MS,
                    ..
                })
            ));
        }
    }

    #[test]
    fn a_host_timestamp_request_is_answered_with_the_vendor_control_and_then_read_again() {
        let mut exchange = Exchange::new(command(cmd::CHALLENGE));
        exchange.on_io_result(IoReply::Completed);

        // The sensor asks for the clock before announcing anything.
        exchange.on_io_result(IoReply::Data(
            timestamp::HOST_TIMESTAMP_INTERRUPT.to_le_bytes().to_vec(),
        ));
        let control = exchange.next_transfer().expect("a control transfer");
        let (value, index, request, request_type) = match control {
            Transfer::ControlOut {
                value,
                index,
                request,
                request_type,
                timeout_ms,
            } => {
                assert_eq!(timeout_ms, timestamp::SYNC_TIMEOUT_MS);
                (value, index, request, request_type)
            }
            other => panic!("expected the timestamp control, got {other:?}"),
        };
        assert_eq!(request_type, timestamp::HOST_TIMESTAMP_REQUEST_TYPE);
        assert_eq!(request, timestamp::HOST_TIMESTAMP_REQUEST);

        // The packed word is the vendor's civil-time encoding: the fields are in their ranges.
        let packed = u32::from(value) | (u32::from(index) << 16);
        let day = packed & 0x1f;
        let month = (packed >> 5) & 0x0f;
        let hour = (packed >> 15) & 0x1f;
        let minute = (packed >> 20) & 0x3f;
        let second = (packed >> 26) & 0x3f;
        assert!((1..=31).contains(&day), "day {day}");
        assert!((1..=12).contains(&month), "month {month}");
        assert!(hour < 24, "hour {hour}");
        assert!(minute < 60, "minute {minute}");
        assert!(second < 60, "second {second}");

        // Answering it returns to the interrupt read; the real announcement then arrives.
        exchange.on_io_result(IoReply::Completed);
        assert!(matches!(
            exchange.next_transfer(),
            Some(Transfer::InterruptIn { .. })
        ));
        exchange.on_io_result(IoReply::Data(announcement(0, 0)));
        assert_eq!(
            exchange.outcome(),
            Some(Ok(Reply {
                status: 0,
                body: Vec::new(),
            }))
        );
    }

    #[test]
    fn a_failed_timestamp_answer_is_its_own_stage() {
        let mut exchange = Exchange::new(command(cmd::CHALLENGE));
        exchange.on_io_result(IoReply::Completed);
        exchange.on_io_result(IoReply::Data(
            timestamp::HOST_TIMESTAMP_INTERRUPT.to_le_bytes().to_vec(),
        ));
        exchange.on_io_result(IoReply::Failed(IoFailure::Stall));

        assert_eq!(
            exchange.outcome(),
            Some(Err(WireError::Control(IoFailure::Stall)))
        );
    }

    #[test]
    fn repeated_timestamp_requests_stop_at_the_bound() {
        let mut exchange = Exchange::new(command(cmd::CHALLENGE));
        exchange.on_io_result(IoReply::Completed);
        for _ in 0..MAX_REQUESTS {
            exchange.on_io_result(IoReply::Data(
                timestamp::HOST_TIMESTAMP_INTERRUPT.to_le_bytes().to_vec(),
            ));
            exchange.on_io_result(IoReply::Completed);
        }
        exchange.on_io_result(IoReply::Data(
            timestamp::HOST_TIMESTAMP_INTERRUPT.to_le_bytes().to_vec(),
        ));

        assert_eq!(
            exchange.outcome(),
            Some(Err(WireError::TooManyTimestampRequests))
        );
    }

    #[test]
    fn a_finished_exchange_asks_for_nothing_and_ignores_late_results() {
        let mut exchange = Exchange::new(command(cmd::CHALLENGE));
        exchange.on_io_result(IoReply::Failed(IoFailure::Timeout));
        assert_eq!(exchange.next_transfer(), None);

        let before = exchange.outcome();
        exchange.on_io_result(IoReply::Data(vec![1]));
        assert_eq!(exchange.outcome(), before, "a late result changes nothing");
    }

    #[test]
    fn a_cancelled_exchange_becomes_the_core_cancellation_event() {
        let outcome = Err(WireError::Out(IoFailure::Cancelled));
        assert_eq!(event_from_outcome(outcome), Event::Cancelled);
    }

    #[test]
    fn a_body_reaches_the_core_with_the_status_from_its_header() {
        let body = frame::build_plain_reply(cmd::VERIFY, attr::CAPTURE, 7, 0x0f, &[0u8; 32]);
        let event = event_from_outcome(Ok(Reply {
            status: 2,
            body: body.clone(),
        }));
        assert_eq!(
            event,
            Event::Reply { status: 0x0f, body },
            "the announcement status is not the command status"
        );
    }
}

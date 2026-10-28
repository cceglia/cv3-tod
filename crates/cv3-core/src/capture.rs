//! Arming a capture, waiting for the finger, and reading the sample hash.
//!
//! A capture is the one primitive verification and enrolment both stand on. The wrapped `0x66`
//! arms it; the sensor then reads the finger asynchronously and signals the read on the interrupt
//! endpoint. The arm reply itself is wrapped and carries the **sample hash**, a 20-byte TLV value
//! inside the decrypted plaintext, which identifies the captured image.
//!
//! ```text
//! host → sensor  0x66 wrapped, attr 0x47   TLV 36 bytes, plaintext 80 bytes
//!                                       (0,4,handle) (0,4,1) (0,4,0x23)
//! sensor → host  wrapped reply             20-byte sample hash somewhere in the plaintext
//! sensor → host  interrupt event 0x03      the finger was read
//! ```
//!
//! [`Capture`] performs the arm, interprets the reply and waits for the finger. A successful
//! capture keeps the session open so the caller can submit the sample or match it; every failure
//! runs [`crate::session::Teardown`] (cancel, then close) before finishing, so no handle is left
//! dangling. A `0x85` reply means a capture is already armed; it is its own outcome, never a
//! capture, and this operation does not silently cancel and retry (ticket 08 owns that).

use std::fmt;

use crate::crypto;
use crate::event::{Action, Event, TransportError};
use crate::operation::Operation;
use crate::proto::{self, attr, cmd};
use crate::session::{Session, Teardown, UnwrapError, WrapError};

/// Length of the sample hash the arm reply carries.
pub const SAMPLE_HASH_LEN: usize = 20;
/// Length of the `0x66` parameter block.
pub const CAPTURE_TLV_LEN: usize = 36;
/// Plaintext length the reference sends with `0x66`: four AES blocks plus one padding block.
pub const CAPTURE_PLAINTEXT_LEN: usize = 80;

/// The largest TLV tag the sample-hash search accepts. The arm reply's own tags are 0, 1 and 2.
const TLV_MAX_TAG: u32 = 3;

/// The 36-byte `0x66` parameter block: `(0,4,handle) (0,4,1) (0,4,0x23)`.
pub fn capture_tlv(handle: u32) -> [u8; CAPTURE_TLV_LEN] {
    let mut tlv = [0u8; CAPTURE_TLV_LEN];
    for length_at in [4usize, 16, 28] {
        tlv[length_at..length_at + 4].copy_from_slice(&4u32.to_le_bytes());
    }
    tlv[8..12].copy_from_slice(&handle.to_le_bytes());
    tlv[20..24].copy_from_slice(&1u32.to_le_bytes());
    tlv[32..36].copy_from_slice(&0x23u32.to_le_bytes());
    tlv
}

/// Finds the first `len`-byte TLV value in a decrypted reply.
///
/// The scan moves four bytes at a time and accepts a `u32 tag <= 3` followed by `u32 length == len`.
/// Every bound is checked against the buffer, so a short, truncated or arbitrary plaintext returns
/// `None` instead of panicking.
pub fn find_tlv_value(plaintext: &[u8], len: usize) -> Option<&[u8]> {
    let mut at = 0usize;
    while at + 8 <= plaintext.len() {
        let tag = le32(plaintext, at);
        let declared = le32(plaintext, at + 4) as usize;
        let value_at = at + 8;
        if tag <= TLV_MAX_TAG
            && declared == len
            && let Some(end) = value_at.checked_add(len)
            && end <= plaintext.len()
        {
            return Some(&plaintext[value_at..end]);
        }
        at += 4;
    }
    None
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// A successful capture: the sample's identifier and the still-open session.
#[derive(Debug, PartialEq, Eq)]
pub struct CapturedSample {
    /// The 20-byte sample hash the sensor returned for this capture.
    pub sample_hash: [u8; SAMPLE_HASH_LEN],
    /// The session, still open, at the sequence the next wrapped command must carry.
    pub session: Session,
}

/// Why a capture did not produce a sample hash.
///
/// The variants are distinct on purpose: a hardware run can tell "the sensor already has a capture
/// armed" from "the finger never arrived" without reading the message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The sensor answered `0x66` with `0x85`: a capture is already armed.
    AlreadyPending,
    /// The arm succeeded but its decrypted reply carried no 20-byte TLV value.
    NoSampleHash,
    /// The sensor answered the arm with a body-less reply.
    MissingReply,
    /// The sensor answered the arm with another non-zero status.
    SensorStatus(u32),
    /// The reply body could not be validated or decrypted.
    MalformedReply(UnwrapError),
    /// The wrapped command could not be built (a host-side programming error).
    Build(WrapError),
    /// No finger event arrived within the transport's finger timeout.
    FingerTimeout,
    /// The transport failed.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPending => f.write_str(
                "a capture is already armed on the sensor (status 0x85); this run captured nothing",
            ),
            Self::NoSampleHash => f.write_str(
                "the sensor armed the capture but its reply carried no 20-byte sample hash",
            ),
            Self::MissingReply => {
                f.write_str("sensor answered the 0x66 capture arm without a body")
            }
            Self::SensorStatus(status) => {
                write!(
                    f,
                    "sensor rejected the 0x66 capture arm with status {status:#04x}"
                )
            }
            Self::MalformedReply(error) => write!(f, "malformed 0x66 capture reply: {error}"),
            Self::Build(error) => {
                write!(f, "cannot build the wrapped 0x66 capture command: {error}")
            }
            Self::FingerTimeout => f.write_str("no finger event arrived within the finger timeout"),
            Self::Transport(error) => write!(f, "transport failed: {error}"),
            Self::Cancelled => f.write_str("capture cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event while capturing"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for CaptureError {}

type CaptureOutcome = Result<CapturedSample, CaptureError>;

#[derive(Debug)]
enum CaptureState {
    NotStarted,
    WaitingArm,
    WaitingFinger {
        sample_hash: [u8; SAMPLE_HASH_LEN],
    },
    /// The original error is held until the best-effort teardown has run.
    TearingDown {
        original: CaptureError,
        teardown: Teardown,
    },
    Done,
}

/// The wrapped `0x66` arm, the reply, and the finger wait.
///
/// The operation owns the [`Session`] it was built with and returns it unchanged on success. On
/// every failure it drops the key material and runs [`Teardown`] (sessionless `0x68`, then `0x04`)
/// before finishing with the original error; a teardown failure never replaces that error.
pub struct Capture {
    session: Option<Session>,
    handle: u32,
    iv: [u8; crypto::BLOCK_LEN],
    state: CaptureState,
}

impl Capture {
    /// Builds a capture for a live session. The probe supplies the IV from the operating system.
    pub fn new(session: Session, iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            iv,
            state: CaptureState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: CaptureOutcome) -> Action<CaptureOutcome> {
        self.state = CaptureState::Done;
        Action::Finish(outcome)
    }

    /// Drops the session and starts the cancel-then-close teardown, preserving `error`.
    fn begin_teardown(&mut self, error: CaptureError) -> Action<CaptureOutcome> {
        self.session = None;
        let mut teardown = Teardown::new(self.handle);
        match teardown.start() {
            Action::Send(frame) => {
                self.state = CaptureState::TearingDown {
                    original: error,
                    teardown,
                };
                Action::Send(frame)
            }
            // A zero handle has nothing to tear down; any other action cannot come from Teardown.
            _ => self.finish(Err(error)),
        }
    }

    fn arm_frame(&self, session: &Session) -> Result<Vec<u8>, WrapError> {
        session.wrap(
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &capture_tlv(session.handle),
            CAPTURE_PLAINTEXT_LEN,
            &self.iv,
            session.next_sequence(),
        )
    }

    fn on_arm_reply(&mut self, status: u32, body: Vec<u8>) -> Action<CaptureOutcome> {
        // The one sequence predicate applies to this reply before it is interpreted; a body
        // advances the counter unless the sensor said 0x0F, which includes a 0x85 reply.
        let has_body = !body.is_empty();
        if let Some(session) = self.session.as_mut() {
            session.note_wrapped_reply(has_body, status);
        }

        if status == proto::status::CAPTURE_PENDING {
            return self.begin_teardown(CaptureError::AlreadyPending);
        }
        if status != proto::status::OK {
            return self.begin_teardown(CaptureError::SensorStatus(status));
        }
        if body.is_empty() {
            return self.begin_teardown(CaptureError::MissingReply);
        }

        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(CaptureError::AlreadyFinished));
        };
        let reply = match session.key().unwrap(&body) {
            Ok(reply) => reply,
            Err(error) => return self.begin_teardown(CaptureError::MalformedReply(error)),
        };
        let Some(value) = find_tlv_value(&reply.plaintext, SAMPLE_HASH_LEN) else {
            return self.begin_teardown(CaptureError::NoSampleHash);
        };
        let mut sample_hash = [0u8; SAMPLE_HASH_LEN];
        sample_hash.copy_from_slice(value);

        self.state = CaptureState::WaitingFinger { sample_hash };
        Action::WaitFinger
    }
}

impl Operation for Capture {
    type Output = CaptureOutcome;

    fn start(&mut self) -> Action<CaptureOutcome> {
        if !matches!(self.state, CaptureState::NotStarted) {
            return self.finish(Err(CaptureError::AlreadyFinished));
        }
        let built = match self.session.as_ref() {
            Some(session) => self.arm_frame(session),
            None => return self.finish(Err(CaptureError::AlreadyFinished)),
        };
        match built {
            Ok(frame) => {
                self.state = CaptureState::WaitingArm;
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(CaptureError::Build(error)),
        }
    }

    fn step(&mut self, event: Event) -> Action<CaptureOutcome> {
        match std::mem::replace(&mut self.state, CaptureState::Done) {
            CaptureState::NotStarted => self.finish(Err(CaptureError::UnexpectedEvent)),
            CaptureState::WaitingArm => match event {
                Event::Reply { status, body } => self.on_arm_reply(status, body),
                Event::ReplyWithoutBody => {
                    if let Some(session) = self.session.as_mut() {
                        session.note_wrapped_reply(false, 0);
                    }
                    self.begin_teardown(CaptureError::MissingReply)
                }
                Event::Transport(error) => self.begin_teardown(CaptureError::Transport(error)),
                Event::Cancelled => self.begin_teardown(CaptureError::Cancelled),
                Event::Finger => self.begin_teardown(CaptureError::UnexpectedEvent),
            },
            CaptureState::WaitingFinger { sample_hash } => match event {
                Event::Finger => match self.session.take() {
                    Some(session) => self.finish(Ok(CapturedSample {
                        sample_hash,
                        session,
                    })),
                    None => self.finish(Err(CaptureError::AlreadyFinished)),
                },
                // A timeout here is the finger not arriving; the transport maps it onto the same
                // timeout event as any other transfer, so this state is what tells them apart.
                Event::Transport(TransportError::Timeout) => {
                    self.begin_teardown(CaptureError::FingerTimeout)
                }
                Event::Transport(error) => self.begin_teardown(CaptureError::Transport(error)),
                Event::Cancelled => self.begin_teardown(CaptureError::Cancelled),
                Event::Reply { .. } | Event::ReplyWithoutBody => {
                    self.begin_teardown(CaptureError::UnexpectedEvent)
                }
            },
            CaptureState::TearingDown {
                original,
                mut teardown,
            } => match teardown.step(event) {
                Action::Send(frame) => {
                    self.state = CaptureState::TearingDown { original, teardown };
                    Action::Send(frame)
                }
                // Teardown never waits; treat anything but a send as its end.
                _ => self.finish(Err(original)),
            },
            CaptureState::Done => self.finish(Err(CaptureError::AlreadyFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capture_tlv_matches_the_wire_layout() {
        let tlv = capture_tlv(0x1122_3344);

        assert_eq!(tlv.len(), 36);
        assert_eq!(&tlv[0..4], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[4..8], &4u32.to_le_bytes(), "value length 4");
        assert_eq!(&tlv[8..12], &0x1122_3344u32.to_le_bytes(), "handle");
        assert_eq!(&tlv[12..16], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[16..20], &4u32.to_le_bytes(), "value length 4");
        assert_eq!(&tlv[20..24], &1u32.to_le_bytes(), "value 1");
        assert_eq!(&tlv[24..28], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[28..32], &4u32.to_le_bytes(), "value length 4");
        assert_eq!(&tlv[32..36], &0x23u32.to_le_bytes(), "value 0x23");
    }

    fn tagged(offset: usize, tag: u32, len: u32, value: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; offset + 8 + value.len()];
        out[offset..offset + 4].copy_from_slice(&tag.to_le_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&len.to_le_bytes());
        out[offset + 8..].copy_from_slice(value);
        out
    }

    #[test]
    fn a_twenty_byte_value_at_the_start_of_a_plaintext_is_found() {
        let value = [0xABu8; 20];
        let plaintext = tagged(0, 0, 20, &value);

        assert_eq!(find_tlv_value(&plaintext, 20), Some(value.as_slice()));
    }

    #[test]
    fn the_scan_moves_four_bytes_at_a_time_and_finds_a_later_value() {
        let value = [0xCDu8; 20];
        // A preceding 8-byte TLV whose tag is 0 but whose length is 4 must be skipped.
        let mut plaintext = tagged(0, 0, 4, &[1, 2, 3, 4]);
        plaintext.extend_from_slice(&tagged(0, 0, 20, &value));

        assert_eq!(find_tlv_value(&plaintext, 20), Some(value.as_slice()));
    }

    #[test]
    fn only_a_tag_at_most_three_and_the_wanted_length_match() {
        let value = [0x11u8; 20];
        assert_eq!(
            find_tlv_value(&tagged(0, 4, 20, &value), 20),
            None,
            "a tag above 3 is not a parameter"
        );
        assert_eq!(
            find_tlv_value(&tagged(0, 0, 19, &value), 20),
            None,
            "a different declared length is not this value"
        );
        assert_eq!(
            find_tlv_value(&tagged(0, 0, 20, &value[..19]), 20),
            None,
            "a value that does not fit the buffer is not returned"
        );
    }

    #[test]
    fn short_and_truncated_plaintexts_return_none_without_panicking() {
        for bytes in [&[][..], &[0u8; 7][..], &[0u8; 8][..], &[0u8; 27][..]] {
            assert_eq!(find_tlv_value(bytes, 20), None);
        }

        let mut lying = tagged(0, 0, 20, &[0u8; 20]);
        lying.truncate(20);
        assert_eq!(find_tlv_value(&lying, 20), None);
    }
}

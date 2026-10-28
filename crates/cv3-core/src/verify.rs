//! Verification: the wrapped `0x73` match, and the capture-then-match composition.
//!
//! ```text
//! host → sensor  0x66 wrapped, attr 0x47   arm a capture (a [`Capture`])
//! sensor → host                             the finger event
//! host → sensor  0x73 wrapped, attr 0x47   TLV 68 bytes, plaintext 112 bytes
//! sensor → host  wrapped reply             verdict word at plaintext +8,
//!                                          20-byte value at plaintext +32 when long enough
//! ```
//!
//! [`Match`] sends the exact 68-byte request the audited reference sends. The block is
//! **firmware-shaped, not a well-formed TLV list**: its last entry, `(3, 20)`, declares twenty
//! value bytes that are not there, and the block ends at that eight-byte header. Reproducing it
//! byte for byte is the point; a "corrected" TLV list is a different request.
//!
//! The reply is wrapped and carries no MAC. Its plaintext is read at fixed offsets, never by
//! scanning: the verdict word is the `u32` at `+8` and the value is the twenty bytes at `+32`
//! when the plaintext is at least 52 bytes long. A reply too short for the verdict word is
//! [`MatchError::MissingVerdict`], deliberately not a no-match.
//!
//! # What the verdict is not
//!
//! The 20-byte value at `+32` is reported as [`Verdict::value`]; its meaning is unestablished and
//! it is not interpreted here as an id or a binding. The reference calls it a biometric-derived
//! hash; the SPEC says the driver assumes nothing about it until ticket 09 measures it. The id
//! comparison that makes a match belong to a specific print is ticket 10's work and is not
//! implemented here: [`Verdict::matched`] is derived from the verdict word alone, and a later
//! ticket must not mistake the value for a binding.
//!
//! # Teardown
//!
//! [`Match`] returns the still-open [`Session`] on success. Every failure runs the sessionless
//! `0x68` cancel and then the `0x04` close before the original error is returned; a teardown
//! failure never replaces that error. [`Verify`] composes one [`Capture`] and one [`Match`], so
//! each primitive has one implementation and each tears its own session down on failure. When a
//! capture fails, its teardown has already run and [`Verify`] does not repeat it.

use std::fmt;

use crate::capture::{Capture, CaptureError, CapturedSample};
use crate::crypto;
use crate::event::{Action, Event, TransportError};
use crate::operation::Operation;
use crate::proto::{self, attr, cmd};
use crate::session::{Session, Teardown, UnwrapError, WrapError};

/// Length of the `0x73` parameter block, exactly as the reference sends it.
pub const MATCH_TLV_LEN: usize = 68;
/// Plaintext length the reference sends with `0x73`.
pub const MATCH_PLAINTEXT_LEN: usize = 112;
/// Length of the value at plaintext `+32`.
pub const MATCH_VALUE_LEN: usize = 20;
/// Offset of the little-endian verdict word inside the decrypted plaintext.
pub const VERDICT_OFFSET: usize = 8;
/// Offset of the 20-byte value inside the decrypted plaintext.
pub const VALUE_OFFSET: usize = 32;
/// The verdict word that means "match".
pub const VERDICT_MATCH: u32 = 1;
/// The verdict word that means "no match".
pub const VERDICT_NO_MATCH: u32 = 0;

/// The 68-byte `0x73` parameter block, reproduced from the reference.
///
/// Five `(tag, 4, value)` entries then `(3, 20)` with **no value bytes**: the last eight bytes are
/// only the tag and length. The block is deliberately not a well-formed TLV list.
pub fn match_tlv(handle: u32) -> [u8; MATCH_TLV_LEN] {
    let mut tlv = [0u8; MATCH_TLV_LEN];
    let entries: [(usize, u32, u32); 5] = [
        (0, 0, handle),
        (12, 0, 0x148),
        (24, 0, 0x53e2),
        (36, 0, 0),
        (48, 2, 0x007b_0ad3),
    ];
    for (at, tag, value) in entries {
        tlv[at..at + 4].copy_from_slice(&tag.to_le_bytes());
        tlv[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes());
        tlv[at + 8..at + 12].copy_from_slice(&value.to_le_bytes());
    }
    // The final entry declares a 20-byte value and supplies none; the block ends here.
    tlv[60..64].copy_from_slice(&3u32.to_le_bytes());
    tlv[64..68].copy_from_slice(&(MATCH_VALUE_LEN as u32).to_le_bytes());
    tlv
}

/// A decoded `0x73` reply.
///
/// `word` is preserved exactly as the sensor sent it. Only [`VERDICT_MATCH`] counts as a match;
/// every other word, including an unexpected one, is reported as a no-match with the raw word
/// available, so an undefined value can never silently authenticate. `value` is the twenty bytes
/// at plaintext `+32`, present only when the plaintext is long enough; its meaning is
/// **unestablished** and it is not an id or a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The raw little-endian verdict word at plaintext `+8`.
    pub word: u32,
    /// `word == 1`. The flag alone; no id comparison is performed here.
    pub matched: bool,
    /// The twenty bytes at plaintext `+32`, when the plaintext carries them.
    pub value: Option<[u8; MATCH_VALUE_LEN]>,
    /// The full decrypted plaintext length, before any interpretation.
    pub plaintext_len: usize,
    /// The raw wrapped reply body length, header included.
    pub reply_len: usize,
}

/// A successful match and the session it leaves open.
#[derive(Debug, PartialEq, Eq)]
pub struct Verification {
    /// What the sensor answered.
    pub verdict: Verdict,
    /// The session, still open, at the sequence the `0x73` reply left it at.
    pub session: Session,
}

/// Why a match did not produce a verdict.
///
/// Every variant is distinct on purpose: a hardware run can tell a refused command, a bodyless
/// reply, a reply too short for its verdict word, an undecryptable reply, a transport failure, a
/// cancellation and an unexpected event without reading the message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    /// The sensor rejected the wrap sequence (`0x0F`).
    WrongSequence,
    /// The sensor answered `0x73` with another non-zero status.
    SensorStatus(u32),
    /// The command completed without an announced body.
    MissingReply,
    /// The reply decrypted, but it is too short to carry the verdict word at `+8`.
    MissingVerdict {
        plaintext_len: usize,
        reply_len: usize,
    },
    /// The reply body could not be validated or decrypted.
    MalformedReply(UnwrapError),
    /// The wrapped command could not be built (a host-side programming error).
    Build(WrapError),
    /// The transport failed.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSequence => f.write_str(
                "sensor rejected the wrap sequence (status 0x0f) on the 0x73 match: the command \
                 carried a stale or unexpected sequence",
            ),
            Self::SensorStatus(status) => {
                write!(
                    f,
                    "sensor rejected the 0x73 match with status {status:#04x}"
                )
            }
            Self::MissingReply => f.write_str("sensor answered the 0x73 match without a body"),
            Self::MissingVerdict {
                plaintext_len,
                reply_len,
            } => write!(
                f,
                "the 0x73 reply decrypted to {plaintext_len} bytes, too short for the verdict \
                 word at +{VERDICT_OFFSET} (reply was {reply_len} bytes); this is not a no-match"
            ),
            Self::MalformedReply(error) => write!(f, "malformed 0x73 match reply: {error}"),
            Self::Build(error) => {
                write!(f, "cannot build the wrapped 0x73 match command: {error}")
            }
            Self::Transport(error) => write!(f, "transport failed during the 0x73 match: {error}"),
            Self::Cancelled => f.write_str("match cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event while waiting for the match"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for MatchError {}

type MatchOutcome = Result<Verification, MatchError>;

#[derive(Debug)]
enum MatchState {
    NotStarted,
    WaitingReply,
    /// The original error is held until the best-effort teardown has run.
    TearingDown {
        original: MatchError,
        teardown: Teardown,
    },
    Done,
}

/// The wrapped `0x73` match.
///
/// The operation owns the [`Session`] it was built with and returns it on success. `iv` is the
/// CBC IV for this one request; the probe draws it from the operating system.
pub struct Match {
    session: Option<Session>,
    handle: u32,
    iv: [u8; crypto::BLOCK_LEN],
    state: MatchState,
}

impl Match {
    /// Builds a match for a live session that has already captured a finger.
    pub fn new(session: Session, iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            iv,
            state: MatchState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: MatchOutcome) -> Action<MatchOutcome> {
        self.state = MatchState::Done;
        Action::Finish(outcome)
    }

    /// Drops the session and starts the cancel-then-close teardown, preserving `error`.
    fn begin_teardown(&mut self, error: MatchError) -> Action<MatchOutcome> {
        self.session = None;
        let mut teardown = Teardown::new(self.handle);
        match teardown.start() {
            Action::Send(frame) => {
                self.state = MatchState::TearingDown {
                    original: error,
                    teardown,
                };
                Action::Send(frame)
            }
            // A zero handle has nothing to tear down; any other action cannot come from Teardown.
            _ => self.finish(Err(error)),
        }
    }

    fn match_frame(&self, session: &Session) -> Result<Vec<u8>, WrapError> {
        session.wrap(
            cmd::MATCH,
            attr::CAPTURE,
            &match_tlv(session.handle),
            MATCH_PLAINTEXT_LEN,
            &self.iv,
            session.next_sequence(),
        )
    }

    fn on_reply(&mut self, status: u32, body: Vec<u8>) -> Action<MatchOutcome> {
        // The one sequence predicate applies before the reply is interpreted: a body advances the
        // counter unless the sensor said 0x0F.
        let has_body = !body.is_empty();
        if let Some(session) = self.session.as_mut() {
            session.note_wrapped_reply(has_body, status);
        }

        if status == proto::status::BAD_SEQUENCE {
            return self.begin_teardown(MatchError::WrongSequence);
        }
        if status != proto::status::OK {
            return self.begin_teardown(MatchError::SensorStatus(status));
        }
        if body.is_empty() {
            return self.begin_teardown(MatchError::MissingReply);
        }

        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(MatchError::AlreadyFinished));
        };
        let reply = match session.key().unwrap(&body) {
            Ok(reply) => reply,
            Err(error) => return self.begin_teardown(MatchError::MalformedReply(error)),
        };
        let plaintext_len = reply.plaintext.len();
        let reply_len = body.len();
        if plaintext_len < VERDICT_OFFSET + 4 {
            return self.begin_teardown(MatchError::MissingVerdict {
                plaintext_len,
                reply_len,
            });
        }

        let word = le32(&reply.plaintext, VERDICT_OFFSET);
        let value = if plaintext_len >= VALUE_OFFSET + MATCH_VALUE_LEN {
            let mut value = [0u8; MATCH_VALUE_LEN];
            value.copy_from_slice(&reply.plaintext[VALUE_OFFSET..VALUE_OFFSET + MATCH_VALUE_LEN]);
            Some(value)
        } else {
            None
        };
        let verdict = Verdict {
            word,
            matched: word == VERDICT_MATCH,
            value,
            plaintext_len,
            reply_len,
        };

        match self.session.take() {
            Some(session) => self.finish(Ok(Verification { verdict, session })),
            None => self.finish(Err(MatchError::AlreadyFinished)),
        }
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

impl Operation for Match {
    type Output = MatchOutcome;

    fn start(&mut self) -> Action<MatchOutcome> {
        if !matches!(self.state, MatchState::NotStarted) {
            return self.finish(Err(MatchError::AlreadyFinished));
        }
        let built = match self.session.as_ref() {
            Some(session) => self.match_frame(session),
            None => return self.finish(Err(MatchError::AlreadyFinished)),
        };
        match built {
            Ok(frame) => {
                self.state = MatchState::WaitingReply;
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(MatchError::Build(error)),
        }
    }

    fn step(&mut self, event: Event) -> Action<MatchOutcome> {
        match std::mem::replace(&mut self.state, MatchState::Done) {
            MatchState::NotStarted => self.finish(Err(MatchError::UnexpectedEvent)),
            MatchState::WaitingReply => match event {
                Event::Reply { status, body } => self.on_reply(status, body),
                Event::ReplyWithoutBody => {
                    if let Some(session) = self.session.as_mut() {
                        session.note_wrapped_reply(false, 0);
                    }
                    self.begin_teardown(MatchError::MissingReply)
                }
                Event::Transport(error) => self.begin_teardown(MatchError::Transport(error)),
                Event::Cancelled => self.begin_teardown(MatchError::Cancelled),
                Event::Finger => self.begin_teardown(MatchError::UnexpectedEvent),
            },
            MatchState::TearingDown {
                original,
                mut teardown,
            } => match teardown.step(event) {
                Action::Send(frame) => {
                    self.state = MatchState::TearingDown { original, teardown };
                    Action::Send(frame)
                }
                // Teardown never waits; anything but another send is its end.
                _ => self.finish(Err(original)),
            },
            MatchState::Done => self.finish(Err(MatchError::AlreadyFinished)),
        }
    }
}

/// Why a verification did not produce a verdict.
///
/// The capture and match primitives already tore the session down on their own failures, so this
/// type only maps them into one vocabulary; it never sends a second teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The arm, the finger wait or the sample-hash read failed; its teardown has run.
    Capture(CaptureError),
    /// The match failed; its teardown has run.
    Match(MatchError),
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => write!(f, "capture failed: {error}"),
            Self::Match(error) => write!(f, "match failed: {error}"),
            Self::UnexpectedEvent => f.write_str("unexpected event during verification"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for VerifyError {}

type VerifyOutcome = Result<Verification, VerifyError>;

enum VerifyState {
    NotStarted,
    Capturing(Capture),
    Matching(Match),
    Done,
}

/// A whole verification: one [`Capture`], then one [`Match`].
///
/// The caller supplies one IV per wrapped request, because the core generates no randomness. On
/// success the session is returned still open; the probe tears it down before exiting. A capture
/// failure has already torn the session down, and so has a match failure, so verification never
/// sends a second cancel-and-close pair for a handle that is already gone.
pub struct Verify {
    session: Option<Session>,
    capture_iv: [u8; crypto::BLOCK_LEN],
    match_iv: [u8; crypto::BLOCK_LEN],
    state: VerifyState,
}

impl Verify {
    /// Builds a verification for a live session.
    ///
    /// `capture_iv` is the IV for the `0x66` arm and `match_iv` the IV for the `0x73` match. They
    /// must differ; the caller draws both from the operating system.
    pub fn new(
        session: Session,
        capture_iv: [u8; crypto::BLOCK_LEN],
        match_iv: [u8; crypto::BLOCK_LEN],
    ) -> Self {
        Self {
            session: Some(session),
            capture_iv,
            match_iv,
            state: VerifyState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: VerifyOutcome) -> Action<VerifyOutcome> {
        self.state = VerifyState::Done;
        Action::Finish(outcome)
    }

    fn start_capture(&mut self) -> Action<VerifyOutcome> {
        let Some(session) = self.session.take() else {
            return self.finish(Err(VerifyError::AlreadyFinished));
        };
        let mut capture = Capture::new(session, self.capture_iv);
        self.advance_capture(capture.start(), capture)
    }

    fn advance_capture(
        &mut self,
        action: Action<Result<CapturedSample, CaptureError>>,
        capture: Capture,
    ) -> Action<VerifyOutcome> {
        match action {
            Action::Send(frame) => {
                self.state = VerifyState::Capturing(capture);
                Action::Send(frame)
            }
            Action::WaitFinger => {
                self.state = VerifyState::Capturing(capture);
                Action::WaitFinger
            }
            Action::Finish(result) => self.on_captured(result),
        }
    }

    fn on_captured(
        &mut self,
        result: Result<CapturedSample, CaptureError>,
    ) -> Action<VerifyOutcome> {
        match result {
            Ok(CapturedSample { session, .. }) => {
                let mut matching = Match::new(session, self.match_iv);
                self.advance_match(matching.start(), matching)
            }
            // The capture already ran its own teardown; repeating it would send a second
            // cancel-and-close pair for a handle that is already gone.
            Err(error) => self.finish(Err(VerifyError::Capture(error))),
        }
    }

    fn advance_match(
        &mut self,
        action: Action<MatchOutcome>,
        matching: Match,
    ) -> Action<VerifyOutcome> {
        match action {
            Action::Send(frame) => {
                self.state = VerifyState::Matching(matching);
                Action::Send(frame)
            }
            Action::WaitFinger => {
                self.state = VerifyState::Matching(matching);
                Action::WaitFinger
            }
            Action::Finish(result) => self.finish(result.map_err(VerifyError::Match)),
        }
    }
}

impl Operation for Verify {
    type Output = VerifyOutcome;

    fn start(&mut self) -> Action<VerifyOutcome> {
        if !matches!(self.state, VerifyState::NotStarted) {
            return self.finish(Err(VerifyError::AlreadyFinished));
        }
        self.start_capture()
    }

    fn step(&mut self, event: Event) -> Action<VerifyOutcome> {
        match std::mem::replace(&mut self.state, VerifyState::Done) {
            VerifyState::NotStarted => self.finish(Err(VerifyError::UnexpectedEvent)),
            VerifyState::Capturing(mut capture) => match capture.step(event) {
                Action::Send(frame) => {
                    self.state = VerifyState::Capturing(capture);
                    Action::Send(frame)
                }
                Action::WaitFinger => {
                    self.state = VerifyState::Capturing(capture);
                    Action::WaitFinger
                }
                Action::Finish(result) => self.on_captured(result),
            },
            VerifyState::Matching(mut matching) => match matching.step(event) {
                Action::Send(frame) => {
                    self.state = VerifyState::Matching(matching);
                    Action::Send(frame)
                }
                Action::WaitFinger => {
                    self.state = VerifyState::Matching(matching);
                    Action::WaitFinger
                }
                Action::Finish(result) => self.finish(result.map_err(VerifyError::Match)),
            },
            VerifyState::Done => self.finish(Err(VerifyError::AlreadyFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_match_tlv_is_the_reference_block_and_ends_at_the_last_header() {
        let tlv = match_tlv(0x1122_3344);

        assert_eq!(tlv.len(), 68);
        assert_eq!(&tlv[0..4], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[4..8], &4u32.to_le_bytes(), "length 4");
        assert_eq!(&tlv[8..12], &0x1122_3344u32.to_le_bytes(), "handle");

        assert_eq!(&tlv[12..16], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[16..20], &4u32.to_le_bytes(), "length 4");
        assert_eq!(&tlv[20..24], &0x148u32.to_le_bytes(), "0x148");

        assert_eq!(&tlv[24..28], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[28..32], &4u32.to_le_bytes(), "length 4");
        assert_eq!(&tlv[32..36], &0x53e2u32.to_le_bytes(), "0x53e2");

        assert_eq!(&tlv[36..40], &0u32.to_le_bytes(), "tag 0");
        assert_eq!(&tlv[40..44], &4u32.to_le_bytes(), "length 4");
        assert_eq!(&tlv[44..48], &0u32.to_le_bytes(), "zero");

        assert_eq!(&tlv[48..52], &2u32.to_le_bytes(), "tag 2");
        assert_eq!(&tlv[52..56], &4u32.to_le_bytes(), "length 4");
        assert_eq!(&tlv[56..60], &0x007b_0ad3u32.to_le_bytes(), "0x007b0ad3");

        assert_eq!(&tlv[60..64], &3u32.to_le_bytes(), "tag 3");
        assert_eq!(&tlv[64..68], &20u32.to_le_bytes(), "declares 20 bytes");
    }

    #[test]
    fn the_last_entry_supplies_no_value_bytes() {
        let tlv = match_tlv(1);
        assert_eq!(
            tlv.len(),
            8 + 5 * 12,
            "five full entries plus one bare header"
        );
    }
}

//! Verification: the wrapped match request, and the capture-then-match composition.
//!
//! ```text
//! host → sensor  0x66 wrapped, attr 0x47   arm a capture (a [`Capture`])
//! sensor → host                             the finger event
//! host → sensor  0x73 wrapped, attr 0x47   identify (or 0x72 for the one-to-one verify)
//! sensor → host  wrapped reply             status 0x00 or 0x89,
//!                                          verdict word at plaintext +8,
//!                                          20-byte value at plaintext +32 when long enough
//! ```
//!
//! # The request
//!
//! Disassembly of the vendor's ControlVault 3 blob shows two commands:
//!
//! - **`0x73` identify** (`cv_do_fingerprint_identify`) is the vendor's one-to-many match. Its
//!   Linux path (`cvif_fingerprint_identify`) calls `cv_fingerprint_identify(handle, 0x48, 0x53e2,
//!   0, count, ids, …)`, so the request names an array of **`u32` template handles**.
//! - **`0x72` verify** (`cv_do_fingerprint_verify`) is the one-to-one variant.
//!
//! `cv_do_fingerprint_identify` builds its parameter list as
//!
//! ```text
//! (0, 4, handle) (0, 4, 0x48) (0, 4, 0x53e2) (0, 4, 0)
//! (2, 4 * count, count × u32 handle)
//! (3, 20, hash)                     only when a hash pointer is supplied
//! ```
//!
//! and each wire entry is `u32 type | u32 size | value bytes` (confirmed by `InitParam_List` and
//! `cvhDecapsulateCmd`). [`request_tlv`] builds exactly that list. The vendor always adds the
//! type-2 entry, so it is present even when the caller names no handle; what a zero-size entry
//! asks the sensor to do is not established, and the next hardware run measures it.
//!
//! The constants this driver used before (`0x148` and `0x7b0ad3`) do not exist in the blob at all.
//! They came from the audited reference, which targets ControlVault 2; `0x53e2` occurs exactly
//! once in the blob, as the argument above. **The corrected request has not been measured on this
//! sensor yet.** The 2026-10-28 runs only established that the old CV2-shaped request was refused
//! (`0x59`), and that completing its last entry changed the status to `0x0E`.
//!
//! The vendor's verify special-cases status `0x89` next to `0x00`, so the driver accepts both as
//! "the sensor answered" and decodes the body. That is all `0x89` is taken to mean: the verdict
//! still comes from the plaintext, and [`Verdict::status`] reports the raw status so a hardware run
//! shows which one the sensor used.
//!
//! The reply is wrapped and carries no MAC. Its plaintext is read at fixed offsets for the verdict
//! word and value, never by scanning for them; the whole plaintext is also kept for the probe's
//! diagnostic dump. A reply too short for the verdict word is [`MatchError::MissingVerdict`],
//! deliberately not a no-match.
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
use crate::session::{Session, TOKEN_LEN, Teardown, UnwrapError, WrapError};

/// Length of the 20-byte value at plaintext `+32`, and of the optional hash entry in the request.
pub const MATCH_VALUE_LEN: usize = 20;
/// Offset of the little-endian verdict word inside the decrypted plaintext.
pub const VERDICT_OFFSET: usize = 8;
/// Offset of the 20-byte value inside the decrypted plaintext.
pub const VALUE_OFFSET: usize = 32;
/// The verdict word that means "match".
pub const VERDICT_MATCH: u32 = 1;
/// The verdict word that means "no match".
pub const VERDICT_NO_MATCH: u32 = 0;

/// Length of the request's fixed part: the four `(0, 4, …)` entries and the type-2 header.
const REQUEST_TLV_BASE_LEN: usize = 56;

/// The identify request's parameter list.
///
/// Four `(0, 4, value)` entries with `handle`, `0x48`, `0x53e2` and zero; one
/// `(2, 4 * handles.len(), handles…)` entry whose values are little-endian `u32` template handles
/// (the entry is present with size zero when the caller names none); and, only when `hash` is
/// `Some`, one `(3, 20, hash)` entry. There is no padding beyond the value bytes, so the length is
/// `56 + 4 * handles.len() + if hash.is_some() { 28 } else { 0 }`.
pub fn request_tlv(handle: u32, handles: &[u32], hash: Option<&[u8; MATCH_VALUE_LEN]>) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(
        REQUEST_TLV_BASE_LEN + 4 * handles.len() + if hash.is_some() { 28 } else { 0 },
    );
    for (tag, value) in [(0u32, handle), (0, 0x48), (0, 0x53e2), (0, 0)] {
        tlv.extend_from_slice(&tag.to_le_bytes());
        tlv.extend_from_slice(&4u32.to_le_bytes());
        tlv.extend_from_slice(&value.to_le_bytes());
    }
    tlv.extend_from_slice(&2u32.to_le_bytes());
    tlv.extend_from_slice(&((4 * handles.len()) as u32).to_le_bytes());
    for handle in handles {
        tlv.extend_from_slice(&handle.to_le_bytes());
    }
    if let Some(hash) = hash {
        tlv.extend_from_slice(&3u32.to_le_bytes());
        tlv.extend_from_slice(&(MATCH_VALUE_LEN as u32).to_le_bytes());
        tlv.extend_from_slice(hash);
    }
    tlv
}

/// The wrapped plaintext length for a `tlv_len`-byte request.
///
/// The TLV is followed by the 32-byte token and rounded up to a whole AES block; [`Session::wrap`]
/// then applies PKCS#7, which always adds at least one more block. For the four request shapes this
/// gives 96 bytes for a 56- or 60-byte TLV and 128 for an 84- or 88-byte one.
fn request_plaintext_len(tlv_len: usize) -> usize {
    let unpadded = tlv_len + TOKEN_LEN;
    unpadded.div_ceil(crypto::BLOCK_LEN) * crypto::BLOCK_LEN
}

/// One wrapped match request: `command`, the vendor's parameter list and its computed plaintext.
///
/// This is the one request builder and it never chooses the command. The probe sends `0x73`
/// identify by default and `0x72` verify when asked; [`Match::with_command`] is the only selector.
pub fn request_frame(
    session: &Session,
    command: u16,
    handles: &[u32],
    hash: Option<&[u8; MATCH_VALUE_LEN]>,
    iv: &[u8; crypto::BLOCK_LEN],
    sequence: u32,
) -> Result<Vec<u8>, WrapError> {
    let tlv = request_tlv(session.handle, handles, hash);
    let plaintext_len = request_plaintext_len(tlv.len());
    session.wrap(command, attr::CAPTURE, &tlv, plaintext_len, iv, sequence)
}

/// A decoded verify reply.
///
/// `word` is preserved exactly as the sensor sent it. Only [`VERDICT_MATCH`] counts as a match;
/// every other word, including an unexpected one, is reported as a no-match with the raw word
/// available, so an undefined value can never silently authenticate. `value` is the twenty bytes
/// at plaintext `+32`, present only when the plaintext is long enough; its meaning is
/// **unestablished** and it is not an id or a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The command the request carried: [`cmd::IDENTIFY`] normally, [`cmd::VERIFY`] on a probe.
    pub command: u16,
    /// The raw status the sensor answered with: `0x00`, or the `0x89` the vendor special-cases.
    pub status: u32,
    /// The raw little-endian verdict word at plaintext `+8`.
    pub word: u32,
    /// `word == 1`. The flag alone; no id comparison is performed here.
    pub matched: bool,
    /// The twenty bytes at plaintext `+32`, when the plaintext carries them.
    pub value: Option<[u8; MATCH_VALUE_LEN]>,
    /// The full decrypted plaintext, for the probe's diagnostic dump.
    ///
    /// Success always carries it; the type is optional so a caller can build a verdict-shaped
    /// value without a body. It is reply data, not key material.
    pub plaintext: Option<Vec<u8>>,
    /// The full decrypted plaintext length, before any interpretation.
    pub plaintext_len: usize,
    /// The raw wrapped reply body length, header included.
    pub reply_len: usize,
}

/// A successful verify and the session it leaves open.
#[derive(Debug, PartialEq, Eq)]
pub struct Verification {
    /// What the sensor answered.
    pub verdict: Verdict,
    /// The session, still open, at the sequence the verify reply left it at.
    pub session: Session,
}

/// Why a verify did not produce a verdict.
///
/// Every variant is distinct on purpose: a hardware run can tell a refused command, a bodyless
/// reply, a reply too short for its verdict word, an undecryptable reply, a transport failure, a
/// cancellation and an unexpected event without reading the message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    /// The sensor rejected the wrap sequence (`0x0F`).
    WrongSequence,
    /// The sensor answered the verify request with a status other than `0x00` or `0x89`.
    ///
    /// The reply length and, when the body decrypted, the plaintext are kept so a hardware run can
    /// see a `0x59` that still carried a body; the message prints the first bytes of the plaintext.
    SensorStatus {
        /// The command the request carried.
        command: u16,
        /// The status word the sensor returned.
        status: u32,
        /// The raw wrapped reply body length, header included (`0` for a body-less reply).
        reply_len: usize,
        /// The decrypted plaintext, when the body was a valid wrapped frame that decrypted.
        plaintext: Option<Vec<u8>>,
    },
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
                "sensor rejected the wrap sequence (status 0x0f) on the verify request: the command \
                 carried a stale or unexpected sequence",
            ),
            Self::SensorStatus {
                command,
                status,
                reply_len,
                plaintext,
            } => {
                write!(
                    f,
                    "sensor rejected the request 0x{command:02x} with status {status:#04x} (raw \
                     reply {reply_len} bytes)"
                )?;
                match plaintext {
                    Some(bytes) => {
                        write!(f, "; decrypted plaintext {} bytes: ", bytes.len())?;
                        write_first_hex(f, bytes)
                    }
                    None if *reply_len == 0 => f.write_str("; the reply carried no body"),
                    None => f.write_str("; the body did not decrypt"),
                }
            }
            Self::MissingReply => f.write_str("sensor answered the verify request without a body"),
            Self::MissingVerdict {
                plaintext_len,
                reply_len,
            } => write!(
                f,
                "the verify reply decrypted to {plaintext_len} bytes, too short for the verdict \
                 word at +{VERDICT_OFFSET} (reply was {reply_len} bytes); this is not a no-match"
            ),
            Self::MalformedReply(error) => write!(f, "malformed verify reply: {error}"),
            Self::Build(error) => {
                write!(f, "cannot build the wrapped verify command: {error}")
            }
            Self::Transport(error) => write!(f, "transport failed during verify: {error}"),
            Self::Cancelled => f.write_str("verify cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event while waiting for the verify reply"),
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

/// The wrapped verify request.
///
/// The operation owns the [`Session`] it was built with and returns it on success. `iv` is the
/// CBC IV for this one request; the probe draws it from the operating system.
pub struct Match {
    session: Option<Session>,
    handle: u32,
    iv: [u8; crypto::BLOCK_LEN],
    handles: Vec<u32>,
    hash: Option<[u8; MATCH_VALUE_LEN]>,
    command: u16,
    state: MatchState,
}

impl Match {
    /// Builds a match for a live session that has already captured a finger.
    ///
    /// The request is the vendor's parameter list from [`request_tlv`] with no handles and no
    /// hash, which asks for a one-to-many match against every stored template. The default command
    /// is [`cmd::VERIFY`]; the probe always selects its command with [`Self::with_command`].
    pub fn new(session: Session, iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            iv,
            handles: Vec::new(),
            hash: None,
            command: cmd::VERIFY,
            state: MatchState::NotStarted,
        }
    }

    /// Adds one `u32` template handle to the request's type-2 array.
    ///
    /// Repeatable: each call appends one entry. The vendor's identify request matches the captured
    /// finger against these handles, in the order supplied. No call sends the type-2 entry with
    /// size zero, which asks the sensor to try every stored template.
    pub fn with_template_handle(mut self, handle: u32) -> Self {
        self.handles.push(handle);
        self
    }

    /// Adds the optional `(3, 20, hash)` entry to the request.
    ///
    /// `None` omits the entry entirely, which is what the vendor builds when it has no hash
    /// pointer. The caller that has a 20-byte hash from an enrolment should pass it.
    pub fn with_template_id(mut self, template_id: Option<[u8; MATCH_VALUE_LEN]>) -> Self {
        self.hash = template_id;
        self
    }

    /// Sends `command` instead of the default [`cmd::VERIFY`].
    ///
    /// [`cmd::IDENTIFY`] (`0x73`) is the vendor's one-to-many match; [`cmd::VERIFY`] (`0x72`) is
    /// the one-to-one variant. The request body is built the same way, so the caller supplies only
    /// the command word.
    pub fn with_command(mut self, command: u16) -> Self {
        self.command = command;
        self
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
        if !answered(status) {
            // A refusal can still carry a body; keep it for the hardware diagnostic instead of
            // discarding it with the status.
            let reply_len = body.len();
            let plaintext = self
                .session
                .as_ref()
                .and_then(|session| session.key().unwrap(&body).ok())
                .map(|reply| reply.plaintext);
            return self.begin_teardown(MatchError::SensorStatus {
                command: self.command,
                status,
                reply_len,
                plaintext,
            });
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
        let plaintext = reply.plaintext;
        let plaintext_len = plaintext.len();
        let reply_len = body.len();
        if plaintext_len < VERDICT_OFFSET + 4 {
            return self.begin_teardown(MatchError::MissingVerdict {
                plaintext_len,
                reply_len,
            });
        }

        let word = le32(&plaintext, VERDICT_OFFSET);
        let value = if plaintext_len >= VALUE_OFFSET + MATCH_VALUE_LEN {
            let mut value = [0u8; MATCH_VALUE_LEN];
            value.copy_from_slice(&plaintext[VALUE_OFFSET..VALUE_OFFSET + MATCH_VALUE_LEN]);
            Some(value)
        } else {
            None
        };
        let verdict = Verdict {
            command: self.command,
            status,
            word,
            matched: word == VERDICT_MATCH,
            value,
            plaintext: Some(plaintext),
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

/// Whether `status` is one the sensor's verify answer carries.
///
/// The vendor's `cv_do_fingerprint_verify` special-cases `0x89` next to success, so both are
/// treated as the sensor having answered; the verdict is still decoded from the body.
fn answered(status: u32) -> bool {
    matches!(status, proto::status::OK | proto::status::VERIFY_ANSWERED)
}

/// Writes at most the first 64 bytes as hex, so a refusal's body cannot flood a terminal.
fn write_first_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    const LIMIT: usize = 64;
    for byte in bytes.iter().take(LIMIT) {
        write!(f, "{byte:02x}")?;
    }
    if bytes.len() > LIMIT {
        f.write_str("...")?;
    }
    Ok(())
}

impl Operation for Match {
    type Output = MatchOutcome;

    fn start(&mut self) -> Action<MatchOutcome> {
        if !matches!(self.state, MatchState::NotStarted) {
            return self.finish(Err(MatchError::AlreadyFinished));
        }
        let built = match self.session.as_ref() {
            Some(session) => request_frame(
                session,
                self.command,
                &self.handles,
                self.hash.as_ref(),
                &self.iv,
                session.next_sequence(),
            ),
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
/// failure has already torn the session down, and so has a verify failure, so verification never
/// sends a second cancel-and-close pair for a handle that is already gone.
pub struct Verify {
    session: Option<Session>,
    capture_iv: [u8; crypto::BLOCK_LEN],
    match_iv: [u8; crypto::BLOCK_LEN],
    handles: Vec<u32>,
    template_id: Option<[u8; MATCH_VALUE_LEN]>,
    command: u16,
    state: VerifyState,
}

impl Verify {
    /// Builds a verification for a live session.
    ///
    /// `capture_iv` is the IV for the `0x66` arm and `match_iv` the IV for the match request.
    /// They must differ; the caller draws both from the operating system. The match request names
    /// no handles and no hash unless the caller adds them, and sends the vendor's `0x72` unless
    /// [`Self::with_command`] selects another command.
    pub fn new(
        session: Session,
        capture_iv: [u8; crypto::BLOCK_LEN],
        match_iv: [u8; crypto::BLOCK_LEN],
    ) -> Self {
        Self {
            session: Some(session),
            capture_iv,
            match_iv,
            handles: Vec::new(),
            template_id: None,
            command: cmd::VERIFY,
            state: VerifyState::NotStarted,
        }
    }

    /// Adds one `u32` template handle to the composed [`Match`] request. Repeatable.
    pub fn with_template_handle(mut self, handle: u32) -> Self {
        self.handles.push(handle);
        self
    }

    /// Adds the optional 20-byte hash entry to the composed [`Match`] request.
    pub fn with_template_id(mut self, template_id: Option<[u8; MATCH_VALUE_LEN]>) -> Self {
        self.template_id = template_id;
        self
    }

    /// Sends `command` on the composed [`Match`] instead of the default [`cmd::VERIFY`].
    pub fn with_command(mut self, command: u16) -> Self {
        self.command = command;
        self
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
                let mut matching = Match::new(session, self.match_iv)
                    .with_template_id(self.template_id)
                    .with_command(self.command);
                for handle in &self.handles {
                    matching = matching.with_template_handle(*handle);
                }
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
    fn the_request_is_the_vendors_parameter_list_without_a_hash() {
        let tlv = request_tlv(0x1122_3344, &[], None);

        assert_eq!(tlv.len(), 56);
        assert_eq!(
            tlv,
            [
                0u8, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, // (0,4,handle)
                0, 0, 0, 0, 4, 0, 0, 0, 0x48, 0, 0, 0, // (0,4,0x48)
                0, 0, 0, 0, 4, 0, 0, 0, 0xe2, 0x53, 0, 0, // (0,4,0x53e2)
                0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, // (0,4,0)
                2, 0, 0, 0, 0, 0, 0, 0, // (2, 0)
            ],
            "four fixed entries and an empty type-2 array"
        );
    }

    #[test]
    fn one_handle_adds_four_little_endian_value_bytes() {
        let tlv = request_tlv(0x1122_3344, &[0x1122_3344], None);

        assert_eq!(tlv.len(), 60);
        assert_eq!(&tlv[48..56], &[2, 0, 0, 0, 4, 0, 0, 0], "type 2, size 4");
        assert_eq!(&tlv[56..60], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&tlv[..48], &request_tlv(0x1122_3344, &[], None)[..48]);
    }

    #[test]
    fn a_hash_alone_adds_a_twenty_byte_type_three_entry() {
        let hash = [0xa5u8; MATCH_VALUE_LEN];
        let tlv = request_tlv(1, &[], Some(&hash));

        assert_eq!(tlv.len(), 84);
        assert_eq!(
            &tlv[48..56],
            &[2, 0, 0, 0, 0, 0, 0, 0],
            "empty type-2 array"
        );
        assert_eq!(&tlv[56..60], &3u32.to_le_bytes(), "type 3");
        assert_eq!(&tlv[60..64], &20u32.to_le_bytes(), "length 20");
        assert_eq!(&tlv[64..84], &hash);
    }

    #[test]
    fn handles_and_a_hash_are_emitted_in_the_vendors_order() {
        let hash = [0x5au8; MATCH_VALUE_LEN];
        let tlv = request_tlv(1, &[0x0102_0304], Some(&hash));

        assert_eq!(tlv.len(), 88);
        assert_eq!(
            &tlv[48..52],
            &2u32.to_le_bytes(),
            "the type-2 entry comes first"
        );
        assert_eq!(
            &tlv[52..56],
            &4u32.to_le_bytes(),
            "one handle is four bytes"
        );
        assert_eq!(&tlv[56..60], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&tlv[60..64], &3u32.to_le_bytes(), "then the hash entry");
        assert_eq!(&tlv[64..68], &20u32.to_le_bytes());
        assert_eq!(&tlv[68..88], &hash);

        assert_eq!(tlv.len(), 56 + 4 + 28);
    }

    #[test]
    fn the_plaintext_is_rounded_up_from_the_tlv_plus_the_token() {
        assert_eq!(request_plaintext_len(56), 96);
        assert_eq!(request_plaintext_len(60), 96);
        assert_eq!(request_plaintext_len(84), 128);
        assert_eq!(request_plaintext_len(88), 128);
        assert_eq!(
            request_plaintext_len(56),
            (56 + TOKEN_LEN).div_ceil(crypto::BLOCK_LEN) * crypto::BLOCK_LEN
        );
    }

    #[test]
    fn the_request_shapes_are_56_60_84_and_88_bytes() {
        let hash = [0u8; MATCH_VALUE_LEN];
        for (handles, hash, expected) in [
            (&[][..], None, 56),
            (&[7][..], None, 60),
            (&[][..], Some(&hash), 84),
            (&[7][..], Some(&hash), 88),
        ] {
            assert_eq!(request_tlv(1, handles, hash).len(), expected);
        }
    }

    #[test]
    fn a_non_zero_status_keeps_the_reply_and_plaintext_for_the_message() {
        let error = MatchError::SensorStatus {
            command: cmd::VERIFY,
            status: 0x59,
            reply_len: 108,
            plaintext: Some(vec![0xab; 52]),
        };
        let text = error.to_string();

        assert!(text.contains("status 0x59"), "{text}");
        assert!(
            text.contains("0x72"),
            "the refused command is named: {text}"
        );
        assert!(text.contains("raw reply 108 bytes"), "{text}");
        assert!(text.contains("decrypted plaintext 52 bytes"), "{text}");
        assert!(text.contains(&"ab".repeat(52)), "{text}");
    }

    #[test]
    fn the_diagnostic_hex_is_bounded_to_the_first_64_bytes() {
        let error = MatchError::SensorStatus {
            command: cmd::IDENTIFY,
            status: 0x59,
            reply_len: 108,
            plaintext: Some(vec![0xcd; 100]),
        };
        let text = error.to_string();

        assert!(text.contains("cd".repeat(64).as_str()), "{text}");
        assert!(!text.contains(&"cd".repeat(65)), "{text}");
        assert!(text.contains("..."), "{text}");
    }

    #[test]
    fn only_the_two_verify_answer_statuses_count_as_answered() {
        assert!(answered(proto::status::OK));
        assert!(answered(proto::status::VERIFY_ANSWERED));
        assert!(!answered(proto::status::RESCAN_A));
        assert!(!answered(0x59));
    }
}

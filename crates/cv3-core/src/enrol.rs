//! A complete enrolment: discard, start, collect samples, and commit.
//!
//! ```text
//! host → sensor  0x6D wrapped, attr 0x45   TLV 12 bytes (0,4,handle), plaintext 48
//! host → sensor  0x8A plain,   attr 0x44   TLV 12 zero bytes
//! repeat:
//!   host → sensor  0x66 wrapped, attr 0x47   (a [`Capture`])
//!   sensor → host  the finger event and the sample hash
//!   host → sensor  0x6C wrapped, attr 0x45   TLV 48: (0,4,handle) (0,20,sample hash) (2,0)
//! host → sensor  0x6E wrapped, attr 0x45   TLV 64: the template id and two more zero fields
//! ```
//!
//! The `0x6C` reply decides what happens next. `0x00` and `0x8F` accept the sample; `0xA4` and
//! `0x89` ask for a rescan and do not count; `0x8C` says the sensor will accept no more samples;
//! any other non-zero status ends the run. An accepted reply whose decrypted plaintext carries a
//! 20-byte value other than the sample hash has completed the enrolment and names the template
//! the sensor stored (the **enrolment id**). Without that signal the operation commits at twelve
//! accepted samples and uses the last sample hash as the template id, recording which of the two
//! it is in [`TemplateSource`]. A caller testing the other answer can call
//! [`Enrol::with_commit_sample_hash`], which commits the last sample hash even when an enrolment
//! id arrived and records [`TemplateSource::ForcedSampleHash`]. That is the probe's
//! `--commit-sample-hash` measurement for ticket 06, not shipping behaviour.
//!
//! ## Composition and progress
//!
//! Each sample is an ordinary [`Capture`], so the arm, the finger wait and the sample-hash read
//! have one implementation. While a capture is in flight this operation owns no [`Session`]: the
//! capture owns it and hands it back on success (or tears it down on failure). Enrolment itself
//! tears the session down on every failure it raises, with the sessionless `0x68` cancel followed
//! by the `0x04` close, and never lets a teardown failure replace the original error.
//!
//! There is no callback. [`Operation::step`] advances [`Enrol::progress`], which a caller that
//! drives the operation itself can read after every step; the probe prints a line per accepted or
//! rejected sample that way.
//!
//! ## IVs
//!
//! CBC needs a distinct IV per wrapped frame, and the core generates no randomness. The caller
//! supplies one random base IV; each frame gets `SHA-256(base || u32le(index))[..16]`. This keeps
//! the interface to one small argument while guaranteeing that no two frames in a run share an IV.

use std::fmt;

use crate::capture::{Capture, CaptureError, CapturedSample, SAMPLE_HASH_LEN, find_tlv_value};
use crate::crypto;
use crate::event::{Action, Event, TransportError};
use crate::frame::{self, FrameError};
use crate::operation::Operation;
use crate::proto::{self, attr, cmd};
use crate::session::{Session, Teardown, UnwrapError, WrapError};

/// Samples the sensor must accept before the operation commits without a completion id.
pub const MAX_ACCEPTED_SAMPLES: usize = 12;
/// Capture arms one run may make before it gives up. The audited reference uses the same cap.
pub const MAX_CAPTURE_ATTEMPTS: usize = 30;

/// Length of the `0x6D` discard parameter block.
pub const DISCARD_TLV_LEN: usize = 12;
/// Plaintext length the reference sends with `0x6D`.
pub const DISCARD_PLAINTEXT_LEN: usize = 48;
/// Length of the `0x8A` start parameter block (all zero).
pub const START_TLV_LEN: usize = 12;
/// Length of the `0x6C` update parameter block.
pub const UPDATE_TLV_LEN: usize = 48;
/// Plaintext length the reference sends with `0x6C`.
pub const UPDATE_PLAINTEXT_LEN: usize = 80;
/// Length of the `0x6E` commit parameter block.
pub const COMMIT_TLV_LEN: usize = 64;
/// Plaintext length the reference sends with `0x6E`.
pub const COMMIT_PLAINTEXT_LEN: usize = 96;
/// Length of a template id (an enrolment id or a sample hash).
pub const TEMPLATE_ID_LEN: usize = SAMPLE_HASH_LEN;

/// The 12-byte `0x6D` parameter block: `(0,4,handle)`.
pub fn discard_tlv(handle: u32) -> [u8; DISCARD_TLV_LEN] {
    let mut tlv = [0u8; DISCARD_TLV_LEN];
    tlv[4..8].copy_from_slice(&4u32.to_le_bytes());
    tlv[8..12].copy_from_slice(&handle.to_le_bytes());
    tlv
}

/// The 12-byte `0x8A` parameter block: all zero.
pub fn start_tlv() -> [u8; START_TLV_LEN] {
    [0u8; START_TLV_LEN]
}

/// The 48-byte `0x6C` parameter block:
/// `(0,4,handle)` then `(0,20,sample_hash)` then `(2,0)`.
pub fn update_tlv(handle: u32, sample_hash: &[u8; SAMPLE_HASH_LEN]) -> [u8; UPDATE_TLV_LEN] {
    let mut tlv = [0u8; UPDATE_TLV_LEN];
    tlv[..DISCARD_TLV_LEN].copy_from_slice(&discard_tlv(handle));
    tlv[16..20].copy_from_slice(&(SAMPLE_HASH_LEN as u32).to_le_bytes());
    tlv[20..40].copy_from_slice(sample_hash);
    tlv[40..44].copy_from_slice(&2u32.to_le_bytes());
    tlv
}

/// The 64-byte `0x6E` parameter block:
/// `(0,4,handle)`, `(0,20,template_id)`, `(2,0)`, `(2,0)`, `(3,0)`.
pub fn commit_tlv(handle: u32, template_id: &[u8; TEMPLATE_ID_LEN]) -> [u8; COMMIT_TLV_LEN] {
    let mut tlv = [0u8; COMMIT_TLV_LEN];
    tlv[..DISCARD_TLV_LEN].copy_from_slice(&discard_tlv(handle));
    tlv[16..20].copy_from_slice(&(TEMPLATE_ID_LEN as u32).to_le_bytes());
    tlv[20..40].copy_from_slice(template_id);
    tlv[40..44].copy_from_slice(&2u32.to_le_bytes());
    tlv[48..52].copy_from_slice(&2u32.to_le_bytes());
    tlv[56..60].copy_from_slice(&3u32.to_le_bytes());
    tlv
}

/// Derives the IV for one wrapped command of an enrolment.
///
/// The caller supplies the random base; the index is the wrapped command's position in the run
/// (discard zero, then one per arm, update and the commit). The result is a deterministic,
/// non-repeating 16-byte value, so no two CBC frames share an IV. The core still generates no
/// randomness.
pub fn enrol_iv(base: &[u8; crypto::BLOCK_LEN], index: u32) -> [u8; crypto::BLOCK_LEN] {
    let mut input = [0u8; crypto::BLOCK_LEN + 4];
    input[..crypto::BLOCK_LEN].copy_from_slice(base);
    input[crypto::BLOCK_LEN..].copy_from_slice(&index.to_le_bytes());
    let digest = crypto::sha256(&input);
    let mut iv = [0u8; crypto::BLOCK_LEN];
    iv.copy_from_slice(&digest[..crypto::BLOCK_LEN]);
    iv
}

/// What the template id in [`EnrolledTemplate`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateSource {
    /// The sensor reported an enrolment id in the `0x6C` reply: the template is named by it.
    EnrolmentId,
    /// The sensor never completed; the last accepted sample hash was used as the template id.
    SampleHash,
    /// The caller forced the last accepted sample hash even though the sensor reported an
    /// enrolment id. This is the probe's `--commit-sample-hash` measurement, not shipping
    /// behaviour: ticket 06 has not established which id the sensor wants.
    ForcedSampleHash,
}

impl fmt::Display for TemplateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnrolmentId => f.write_str("sensor enrolment id"),
            Self::SampleHash => f.write_str("last sample hash"),
            Self::ForcedSampleHash => {
                f.write_str("last sample hash, forced by --commit-sample-hash")
            }
        }
    }
}

/// A committed enrolment and the session it leaves open.
///
/// The session is still open at the sequence the commit reply left it at. The probe tears it down;
/// the binding tickets need it open for the confirmation touch.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrolledTemplate {
    /// The 20-byte id stored in the commit command.
    pub template_id: [u8; TEMPLATE_ID_LEN],
    /// Whether `template_id` is the sensor's enrolment id or the last sample hash.
    pub source: TemplateSource,
    /// Samples the sensor accepted.
    pub accepted_samples: usize,
    /// The live session, with the wrap sequence already advanced by the commit reply.
    pub session: Session,
}

/// How far an enrolment has got, readable after any step.
///
/// The core has no callback: a caller that drives [`Enrol`] itself reads this between steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnrolProgress {
    /// Samples the sensor accepted (`0x00` or `0x8F` replies to `0x6C`).
    pub accepted_samples: usize,
    /// Capture arms sent (`0x66`), including arms whose sample was rejected.
    pub capture_attempts: usize,
    /// Samples the sensor asked to rescan (`0xA4` or `0x89` replies to `0x6C`).
    pub rejected_samples: usize,
}

/// The step an enrolment error happened at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolStage {
    Discard,
    Start,
    Capture,
    Update,
    Commit,
}

impl fmt::Display for EnrolStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("the 0x6d discard"),
            Self::Start => f.write_str("the 0x8a start"),
            Self::Capture => f.write_str("the capture"),
            Self::Update => f.write_str("the 0x6c update"),
            Self::Commit => f.write_str("the 0x6e commit"),
        }
    }
}

/// Why an enrolment did not commit a template.
///
/// The variants are distinct on purpose. Every failure tears the session down before it is
/// returned; [`EnrolError::may_have_stored_template`] says whether the run got as far as sending
/// the commit, and [`EnrolError::pending_enrolment_remains`] says whether a half-finished
/// enrolment may be left on the sensor until the next run's discard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolError {
    /// A command frame could not be built (a host-side programming error).
    Build(WrapError),
    /// A command that must answer with a body answered without one.
    MissingReply { stage: EnrolStage },
    /// The sensor rejected an update with a status that is neither accepted, rescan nor full.
    UpdateRejected { status: u32, accepted: usize },
    /// `0x8C` arrived before twelve accepted samples and without a completion id.
    Incomplete { accepted: usize, required: usize },
    /// The sensor rejected the commit.
    CommitRejected { status: u32 },
    /// A capture (arm, finger wait or sample-hash read) failed; its own teardown has run.
    Capture(CaptureError),
    /// The transport failed while the operation was at `stage`.
    Transport {
        stage: EnrolStage,
        error: TransportError,
    },
    /// The operation was cancelled while at `stage`.
    Cancelled { stage: EnrolStage },
    /// A device reply could not be validated or decrypted.
    MalformedReply {
        stage: EnrolStage,
        error: UnwrapError,
    },
    /// A device reply's frame header was invalid.
    MalformedFrame {
        stage: EnrolStage,
        error: FrameError,
    },
    /// The sensor kept rejecting or failing to produce samples until the attempt cap.
    AttemptLimit { attempts: usize, accepted: usize },
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent { stage: EnrolStage },
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl EnrolError {
    /// Whether the run sent the `0x6E` commit, so a template may now exist on the sensor.
    ///
    /// Only a failure at the commit stage can leave a stored template behind: every earlier
    /// failure happened before the commit was built or sent.
    pub fn may_have_stored_template(&self) -> bool {
        matches!(
            self,
            Self::CommitRejected { .. }
                | Self::MissingReply {
                    stage: EnrolStage::Commit
                }
                | Self::Transport {
                    stage: EnrolStage::Commit,
                    ..
                }
                | Self::Cancelled {
                    stage: EnrolStage::Commit
                }
                | Self::MalformedReply {
                    stage: EnrolStage::Commit,
                    ..
                }
                | Self::MalformedFrame {
                    stage: EnrolStage::Commit,
                    ..
                }
                | Self::UnexpectedEvent {
                    stage: EnrolStage::Commit
                }
        )
    }

    /// Whether a half-finished enrolment may remain on the sensor until the next discard.
    ///
    /// Teardown cancels an armed capture and closes the handle, but it does not discard the
    /// enrolment: only the next run's `0x6D` does. A finished (inert) operation reports nothing.
    pub fn pending_enrolment_remains(&self) -> bool {
        !matches!(self, Self::AlreadyFinished)
    }

    fn notes(&self) -> &'static str {
        match (
            self.may_have_stored_template(),
            self.pending_enrolment_remains(),
        ) {
            (true, true) => {
                "; the commit was attempted, so a template may exist on the sensor; a pending \
                 enrolment may remain until the next discard"
            }
            (false, true) => {
                "; no template was stored; a pending enrolment may remain on the sensor until the \
                 next discard"
            }
            (true, false) => "; the commit was attempted, so a template may exist on the sensor",
            (false, false) => "",
        }
    }
}

impl fmt::Display for EnrolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => write!(f, "cannot build an enrolment command: {error}"),
            Self::MissingReply { stage } => {
                write!(f, "the sensor answered {stage} without a body")
            }
            Self::UpdateRejected { status, accepted } => write!(
                f,
                "sensor rejected the 0x6c update with status {status:#04x} after {accepted} \
                 accepted sample(s)"
            ),
            Self::Incomplete { accepted, required } => write!(
                f,
                "the sensor stopped after {accepted} accepted sample(s) with no completion and no \
                 enrolment id; {required} accepted samples are needed to commit without one"
            ),
            Self::CommitRejected { status } => {
                write!(
                    f,
                    "sensor rejected the 0x6e commit with status {status:#04x}"
                )
            }
            Self::Capture(error) => write!(f, "capture failed: {error}"),
            Self::Transport { stage, error } => {
                write!(f, "transport failed during {stage}: {error}")
            }
            Self::Cancelled { stage } => write!(f, "enrolment cancelled during {stage}"),
            Self::MalformedReply { stage, error } => {
                write!(f, "malformed {stage} reply: {error}")
            }
            Self::MalformedFrame { stage, error } => {
                write!(f, "malformed {stage} reply frame: {error}")
            }
            Self::AttemptLimit { attempts, accepted } => write!(
                f,
                "the sensor produced no usable enrolment after {attempts} capture attempts \
                 ({accepted} accepted sample(s))"
            ),
            Self::UnexpectedEvent { stage } => {
                write!(f, "unexpected event during {stage}")
            }
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }?;
        f.write_str(self.notes())
    }
}

impl std::error::Error for EnrolError {}

type EnrolOutcome = Result<EnrolledTemplate, EnrolError>;

enum EnrolState {
    NotStarted,
    WaitingDiscard,
    WaitingStart,
    /// The capture owns the session until it finishes.
    Capturing(Capture),
    WaitingUpdate {
        sample_hash: [u8; SAMPLE_HASH_LEN],
    },
    WaitingCommit {
        template_id: [u8; TEMPLATE_ID_LEN],
        source: TemplateSource,
    },
    /// The original error is held until the best-effort teardown has run.
    TearingDown {
        original: EnrolError,
        teardown: Teardown,
    },
    Done,
}

/// A whole enrolment, driven only by [`Operation::start`] and [`Operation::step`].
///
/// It begins by discarding any pending enrolment, so a previous abandoned attempt is cleared
/// before this one starts. On success it returns the committed id, its source and the still-open
/// [`Session`]; on failure it tears the session down and returns a distinct [`EnrolError`].
pub struct Enrol {
    session: Option<Session>,
    handle: u32,
    base_iv: [u8; crypto::BLOCK_LEN],
    iv_index: u32,
    state: EnrolState,
    progress: EnrolProgress,
    last_sample_hash: Option<[u8; SAMPLE_HASH_LEN]>,
    commit_sample_hash: bool,
}

impl Enrol {
    /// Builds an enrolment for a live session. `base_iv` is the caller's random IV seed; the
    /// operation derives one IV per wrapped frame from it with [`enrol_iv`].
    pub fn new(session: Session, base_iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            base_iv,
            iv_index: 0,
            state: EnrolState::NotStarted,
            progress: EnrolProgress::default(),
            last_sample_hash: None,
            commit_sample_hash: false,
        }
    }

    /// Commits with the last submitted sample hash even when the sensor reports an enrolment id.
    ///
    /// This is the probe's `--commit-sample-hash` measurement tool for ticket 06: this project has
    /// not established which id the sensor wants in `0x6E`, so this variant lets a hardware run
    /// test the other answer. A commit it makes for this reason records
    /// [`TemplateSource::ForcedSampleHash`]. It is not shipping behaviour.
    pub fn with_commit_sample_hash(mut self) -> Self {
        self.commit_sample_hash = true;
        self
    }

    /// The accepted-sample, attempt and rescan counts, updated after every relevant reply.
    pub fn progress(&self) -> EnrolProgress {
        self.progress
    }

    fn finish(&mut self, outcome: EnrolOutcome) -> Action<EnrolOutcome> {
        self.state = EnrolState::Done;
        Action::Finish(outcome)
    }

    /// Drops the key material and starts the cancel-then-close teardown, preserving `error`.
    fn begin_teardown(&mut self, error: EnrolError) -> Action<EnrolOutcome> {
        self.session = None;
        let mut teardown = Teardown::new(self.handle);
        match teardown.start() {
            Action::Send(frame) => {
                self.state = EnrolState::TearingDown {
                    original: error,
                    teardown,
                };
                Action::Send(frame)
            }
            // A zero handle has nothing to tear down; any other action cannot come from Teardown.
            _ => self.finish(Err(error)),
        }
    }

    fn next_iv(&mut self) -> [u8; crypto::BLOCK_LEN] {
        let iv = enrol_iv(&self.base_iv, self.iv_index);
        self.iv_index = self.iv_index.wrapping_add(1);
        iv
    }

    fn send_start(&mut self) -> Action<EnrolOutcome> {
        self.state = EnrolState::WaitingStart;
        Action::Send(frame::build_plain(
            cmd::START_ENROLMENT,
            attr::ENROLMENT_START,
            0,
            &start_tlv(),
        ))
    }

    /// Starts the next capture, or fails once the attempt cap is reached.
    fn next_capture(&mut self) -> Action<EnrolOutcome> {
        if self.progress.capture_attempts >= MAX_CAPTURE_ATTEMPTS {
            return self.begin_teardown(EnrolError::AttemptLimit {
                attempts: self.progress.capture_attempts,
                accepted: self.progress.accepted_samples,
            });
        }
        let Some(session) = self.session.take() else {
            return self.finish(Err(EnrolError::AlreadyFinished));
        };
        self.progress.capture_attempts += 1;
        let iv = self.next_iv();
        let mut capture = Capture::new(session, iv);
        match capture.start() {
            Action::Send(frame) => {
                self.state = EnrolState::Capturing(capture);
                Action::Send(frame)
            }
            Action::WaitFinger => {
                self.state = EnrolState::Capturing(capture);
                Action::WaitFinger
            }
            Action::Finish(result) => self.on_captured(result),
        }
    }

    fn on_captured(
        &mut self,
        result: Result<CapturedSample, CaptureError>,
    ) -> Action<EnrolOutcome> {
        match result {
            Ok(CapturedSample {
                sample_hash,
                session,
            }) => {
                self.session = Some(session);
                self.last_sample_hash = Some(sample_hash);
                self.begin_update(sample_hash)
            }
            // The capture already ran its own teardown; repeating it would send a second
            // cancel-and-close pair for a handle that is already gone.
            Err(error) => self.finish(Err(capture_failure(error))),
        }
    }

    fn begin_update(&mut self, sample_hash: [u8; SAMPLE_HASH_LEN]) -> Action<EnrolOutcome> {
        let iv = self.next_iv();
        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(EnrolError::AlreadyFinished));
        };
        let wrapped = session.wrap(
            cmd::UPDATE_ENROLMENT,
            attr::SESSION,
            &update_tlv(session.handle, &sample_hash),
            UPDATE_PLAINTEXT_LEN,
            &iv,
            session.next_sequence(),
        );
        match wrapped {
            Ok(frame) => {
                self.state = EnrolState::WaitingUpdate { sample_hash };
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(EnrolError::Build(error)),
        }
    }

    fn on_update(
        &mut self,
        sample_hash: [u8; SAMPLE_HASH_LEN],
        event: Event,
    ) -> Action<EnrolOutcome> {
        match event {
            Event::Reply { status, body } => {
                session_note(self.session.as_mut(), !body.is_empty(), status);
                self.classify_update(sample_hash, status, body)
            }
            Event::ReplyWithoutBody => {
                session_note(self.session.as_mut(), false, 0);
                self.begin_teardown(EnrolError::MissingReply {
                    stage: EnrolStage::Update,
                })
            }
            Event::Transport(error) => self.begin_teardown(EnrolError::Transport {
                stage: EnrolStage::Update,
                error,
            }),
            Event::Cancelled => self.begin_teardown(EnrolError::Cancelled {
                stage: EnrolStage::Update,
            }),
            Event::Finger => self.begin_teardown(EnrolError::UnexpectedEvent {
                stage: EnrolStage::Update,
            }),
        }
    }

    fn classify_update(
        &mut self,
        sample_hash: [u8; SAMPLE_HASH_LEN],
        status: u32,
        body: Vec<u8>,
    ) -> Action<EnrolOutcome> {
        match status {
            proto::status::OK | proto::status::SAMPLE_ACCEPTED => {
                self.accept_sample(sample_hash, &body)
            }
            proto::status::ENROLMENT_FULL => self.enrolment_full(),
            proto::status::RESCAN_A | proto::status::RESCAN_B => {
                self.progress.rejected_samples += 1;
                self.next_capture()
            }
            other => self.begin_teardown(EnrolError::UpdateRejected {
                status: other,
                accepted: self.progress.accepted_samples,
            }),
        }
    }

    fn accept_sample(
        &mut self,
        sample_hash: [u8; SAMPLE_HASH_LEN],
        body: &[u8],
    ) -> Action<EnrolOutcome> {
        self.progress.accepted_samples += 1;
        self.last_sample_hash = Some(sample_hash);

        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(EnrolError::AlreadyFinished));
        };
        let reply = match session.key().unwrap(body) {
            Ok(reply) => reply,
            Err(error) => {
                return self.begin_teardown(EnrolError::MalformedReply {
                    stage: EnrolStage::Update,
                    error,
                });
            }
        };
        // Completion is the sensor naming a template that is not the sample just submitted.
        if let Some(value) = find_tlv_value(&reply.plaintext, TEMPLATE_ID_LEN) {
            let mut template_id = [0u8; TEMPLATE_ID_LEN];
            template_id.copy_from_slice(value);
            if template_id != sample_hash {
                if self.commit_sample_hash {
                    return self.begin_commit(sample_hash, TemplateSource::ForcedSampleHash);
                }
                return self.begin_commit(template_id, TemplateSource::EnrolmentId);
            }
        }

        // No explicit completion: twelve accepted samples are the documented fallback.
        if self.progress.accepted_samples >= MAX_ACCEPTED_SAMPLES {
            return self.begin_commit(sample_hash, TemplateSource::SampleHash);
        }
        self.next_capture()
    }

    fn enrolment_full(&mut self) -> Action<EnrolOutcome> {
        match (self.progress.accepted_samples, self.last_sample_hash) {
            (accepted, Some(template_id)) if accepted >= MAX_ACCEPTED_SAMPLES => {
                self.begin_commit(template_id, TemplateSource::SampleHash)
            }
            (accepted, _) => self.begin_teardown(EnrolError::Incomplete {
                accepted,
                required: MAX_ACCEPTED_SAMPLES,
            }),
        }
    }

    fn begin_commit(
        &mut self,
        template_id: [u8; TEMPLATE_ID_LEN],
        source: TemplateSource,
    ) -> Action<EnrolOutcome> {
        let iv = self.next_iv();
        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(EnrolError::AlreadyFinished));
        };
        let wrapped = session.wrap(
            cmd::COMMIT_ENROLMENT,
            attr::SESSION,
            &commit_tlv(session.handle, &template_id),
            COMMIT_PLAINTEXT_LEN,
            &iv,
            session.next_sequence(),
        );
        match wrapped {
            Ok(frame) => {
                self.state = EnrolState::WaitingCommit {
                    template_id,
                    source,
                };
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(EnrolError::Build(error)),
        }
    }

    fn on_commit(
        &mut self,
        template_id: [u8; TEMPLATE_ID_LEN],
        source: TemplateSource,
        event: Event,
    ) -> Action<EnrolOutcome> {
        match event {
            Event::Reply { status, body } => {
                session_note(self.session.as_mut(), !body.is_empty(), status);
                if status != proto::status::OK {
                    return self.begin_teardown(EnrolError::CommitRejected { status });
                }
                if body.is_empty() {
                    return self.begin_teardown(EnrolError::MissingReply {
                        stage: EnrolStage::Commit,
                    });
                }
                if let Err(error) = frame::validate(&body) {
                    return self.begin_teardown(EnrolError::MalformedFrame {
                        stage: EnrolStage::Commit,
                        error,
                    });
                }
                match self.session.take() {
                    Some(session) => self.finish(Ok(EnrolledTemplate {
                        template_id,
                        source,
                        accepted_samples: self.progress.accepted_samples,
                        session,
                    })),
                    None => self.finish(Err(EnrolError::AlreadyFinished)),
                }
            }
            Event::ReplyWithoutBody => {
                session_note(self.session.as_mut(), false, 0);
                self.begin_teardown(EnrolError::MissingReply {
                    stage: EnrolStage::Commit,
                })
            }
            Event::Transport(error) => self.begin_teardown(EnrolError::Transport {
                stage: EnrolStage::Commit,
                error,
            }),
            Event::Cancelled => self.begin_teardown(EnrolError::Cancelled {
                stage: EnrolStage::Commit,
            }),
            Event::Finger => self.begin_teardown(EnrolError::UnexpectedEvent {
                stage: EnrolStage::Commit,
            }),
        }
    }
}

/// Routes one wrapped reply through the session's single sequence predicate.
fn session_note(session: Option<&mut Session>, has_body: bool, status: u32) {
    if let Some(session) = session {
        session.note_wrapped_reply(has_body, status);
    }
}

/// Maps a capture failure onto the enrolment's own vocabulary, so transport and cancellation
/// keep their meaning at every stage.
fn capture_failure(error: CaptureError) -> EnrolError {
    match error {
        CaptureError::Transport(error) => EnrolError::Transport {
            stage: EnrolStage::Capture,
            error,
        },
        CaptureError::Cancelled => EnrolError::Cancelled {
            stage: EnrolStage::Capture,
        },
        other => EnrolError::Capture(other),
    }
}

impl Operation for Enrol {
    type Output = EnrolOutcome;

    fn start(&mut self) -> Action<EnrolOutcome> {
        if !matches!(self.state, EnrolState::NotStarted) {
            return self.finish(Err(EnrolError::AlreadyFinished));
        }
        let iv = self.next_iv();
        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(EnrolError::AlreadyFinished));
        };
        let built = session.wrap(
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &discard_tlv(session.handle),
            DISCARD_PLAINTEXT_LEN,
            &iv,
            session.next_sequence(),
        );
        match built {
            Ok(frame) => {
                self.state = EnrolState::WaitingDiscard;
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(EnrolError::Build(error)),
        }
    }

    fn step(&mut self, event: Event) -> Action<EnrolOutcome> {
        match std::mem::replace(&mut self.state, EnrolState::Done) {
            EnrolState::NotStarted => self.finish(Err(EnrolError::UnexpectedEvent {
                stage: EnrolStage::Discard,
            })),
            EnrolState::WaitingDiscard => match event {
                Event::Reply { status, body } => {
                    session_note(self.session.as_mut(), !body.is_empty(), status);
                    // The reference does not judge the discard's status: any completed command
                    // means a pending enrolment is gone, and `0x8A` is next either way.
                    self.send_start()
                }
                Event::ReplyWithoutBody => {
                    session_note(self.session.as_mut(), false, 0);
                    self.send_start()
                }
                Event::Transport(error) => self.begin_teardown(EnrolError::Transport {
                    stage: EnrolStage::Discard,
                    error,
                }),
                Event::Cancelled => self.begin_teardown(EnrolError::Cancelled {
                    stage: EnrolStage::Discard,
                }),
                Event::Finger => self.begin_teardown(EnrolError::UnexpectedEvent {
                    stage: EnrolStage::Discard,
                }),
            },
            EnrolState::WaitingStart => match event {
                // `0x8A` is plain and consumes no sequence; its status is not judged either.
                Event::Reply { .. } | Event::ReplyWithoutBody => self.next_capture(),
                Event::Transport(error) => self.begin_teardown(EnrolError::Transport {
                    stage: EnrolStage::Start,
                    error,
                }),
                Event::Cancelled => self.begin_teardown(EnrolError::Cancelled {
                    stage: EnrolStage::Start,
                }),
                Event::Finger => self.begin_teardown(EnrolError::UnexpectedEvent {
                    stage: EnrolStage::Start,
                }),
            },
            EnrolState::Capturing(mut capture) => match capture.step(event) {
                Action::Send(frame) => {
                    self.state = EnrolState::Capturing(capture);
                    Action::Send(frame)
                }
                Action::WaitFinger => {
                    self.state = EnrolState::Capturing(capture);
                    Action::WaitFinger
                }
                Action::Finish(result) => self.on_captured(result),
            },
            EnrolState::WaitingUpdate { sample_hash } => self.on_update(sample_hash, event),
            EnrolState::WaitingCommit {
                template_id,
                source,
            } => self.on_commit(template_id, source, event),
            EnrolState::TearingDown {
                original,
                mut teardown,
            } => match teardown.step(event) {
                Action::Send(frame) => {
                    self.state = EnrolState::TearingDown { original, teardown };
                    Action::Send(frame)
                }
                // Teardown never waits; anything but another send is its end.
                _ => self.finish(Err(original)),
            },
            EnrolState::Done => self.finish(Err(EnrolError::AlreadyFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_discard_update_and_commit_tlvs_match_the_wire_layout() {
        assert_eq!(discard_tlv(1), [0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(start_tlv(), [0u8; START_TLV_LEN]);

        let hash = [0x11u8; SAMPLE_HASH_LEN];
        let update = update_tlv(0x1122_3344, &hash);
        assert_eq!(le32(&update, 0), 0);
        assert_eq!(le32(&update, 4), 4);
        assert_eq!(le32(&update, 8), 0x1122_3344);
        assert_eq!(le32(&update, 12), 0);
        assert_eq!(le32(&update, 16), 20);
        assert_eq!(&update[20..40], &hash);
        assert_eq!(le32(&update, 40), 2);
        assert_eq!(le32(&update, 44), 0);

        let commit = commit_tlv(0x1122_3344, &hash);
        assert_eq!(&commit[..12], &discard_tlv(0x1122_3344));
        assert_eq!(le32(&commit, 12), 0);
        assert_eq!(le32(&commit, 16), 20);
        assert_eq!(&commit[20..40], &hash);
        assert_eq!(le32(&commit, 40), 2);
        assert_eq!(le32(&commit, 44), 0);
        assert_eq!(le32(&commit, 48), 2);
        assert_eq!(le32(&commit, 52), 0);
        assert_eq!(le32(&commit, 56), 3);
        assert_eq!(le32(&commit, 60), 0);
    }

    #[test]
    fn the_iv_derivation_never_repeats_within_a_run() {
        let base = [0x5au8; crypto::BLOCK_LEN];
        let mut seen = std::collections::HashSet::new();
        for index in 0..128 {
            assert!(
                seen.insert(enrol_iv(&base, index)),
                "index {index} repeated"
            );
        }
    }

    #[test]
    fn an_enrolment_full_reply_commits_when_twelve_samples_were_accepted() {
        // The guard is defensive: the operation normally commits on the twelfth accepted reply.
        // This asserts the same decision if `0x8C` is what stops collection instead.
        let session = Session::new(
            0x1122_3344,
            20,
            20,
            20,
            crate::session::SessionKey::from_bytes([0u8; crypto::SESSION_KEY_LEN]),
            4,
        );
        let mut operation = Enrol::new(session, [0u8; crypto::BLOCK_LEN]);
        operation.progress = EnrolProgress {
            accepted_samples: MAX_ACCEPTED_SAMPLES,
            capture_attempts: MAX_ACCEPTED_SAMPLES,
            rejected_samples: 0,
        };
        operation.last_sample_hash = Some([0x42u8; SAMPLE_HASH_LEN]);

        match operation.enrolment_full() {
            Action::Send(frame) => {
                assert_eq!(&frame[8..10], &cmd::COMMIT_ENROLMENT.to_le_bytes());
                assert_eq!(&frame[16..20], &0x1122_3344u32.to_le_bytes());
                assert_eq!(le32(&frame, frame::PARAM_LEN_OFFSET), COMMIT_TLV_LEN as u32);
            }
            other => panic!("expected a commit, got {other:?}"),
        }
        assert_eq!(operation.progress().accepted_samples, MAX_ACCEPTED_SAMPLES);
    }

    fn le32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
    }
}

//! A complete enrolment: collect samples, commit, then bind the print with one confirmation touch.
//!
//! ```text
//! (an [Enrol] run: 0x6D, 0x8A, (0x66, 0x6C) …, 0x6E — see crate::enrol)
//! host → sensor  0x66 wrapped, attr 0x47   arm the confirmation capture
//! sensor → host                             the finger event
//! host → sensor  0x2F wrapped, attr 0x47   identify against the commit reply's template handle
//! sensor → host                             verdict and matched handle
//! ```
//!
//! The commit reply names the template handle the sensor stored; the confirmation touch asks the
//! sensor to match the finger again against that handle. The print is stored only when
//! [`PrintPayload::accepts`] accepts the reply: the exact measured reply shape, verdict `1` and the
//! same handle. A commit reply with no handle, a confirmation that does not happen and a verdict
//! that does not accept are all failures, and the error says the template may remain on the sensor.
//!
//! There is no unbound mode. A print whose confirmation failed is never stored: that is the whole
//! point of the binding, and a degraded mode that trusted the match flag would reopen the
//! cross-user hole the project exists to close (SPEC "No unbound prints").
//!
//! # Stages
//!
//! `libfprint` is told to expect [`ENROL_STAGES`] stages: up to twelve accepted samples plus the
//! confirmation touch, fewer when the sensor completes early. [`EnrolStages::completed`] is what a
//! caller reports after each step; it never exceeds [`ENROL_STAGES`]. The core has no callback, so
//! a caller that drives the operation itself reads [`EnrolAndBind::stages`] between steps, exactly
//! as the probe reads [`crate::enrol::Enrol::progress`].
//!
//! # Session ownership
//!
//! A successful enrolment returns the still-open [`Session`] for the next operation. A failure
//! returns the session too when it survived — a missing commit handle and a rejected confirmation
//! leave the session usable — and `None` when the primitive that failed already tore it down. The
//! caller must not close a session it was not given back.

use std::fmt;

use crate::crypto;
use crate::enrol::{Enrol, EnrolError, EnrolProgress, EnrolledTemplate, MAX_ACCEPTED_SAMPLES};
use crate::event::{Action, Event};
use crate::operation::Operation;
use crate::print::{PRINT_PAYLOAD_LEN, PrintPayload, PrintSource};
use crate::proto::cmd;
use crate::session::Session;
use crate::verify::{Verdict, Verify, VerifyError};

/// Stages `libfprint` is told to expect: up to twelve accepted samples and one confirmation touch.
///
/// The sensor may complete early, so a run reports fewer; it never reports more.
pub const ENROL_STAGES: usize = MAX_ACCEPTED_SAMPLES + 1;

/// The sentence every failure after the commit carries.
///
/// A template committed before a failed confirmation may remain on the sensor: without the
/// inventory the driver cannot identify it, and without a delete command it cannot remove it. The
/// driver says so instead of claiming a clean failure (SPEC "No unbound prints").
pub const TEMPLATE_MAY_REMAIN: &str = "the template may remain on the sensor, and this driver \
                                      cannot identify or remove it yet";

/// How far a whole enrolment has got, readable after any step.
///
/// This is [`EnrolProgress`] plus the confirmation, so a caller sees both the samples the sensor
/// accepted and the binding touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnrolStages {
    /// Samples the sensor accepted.
    pub accepted_samples: usize,
    /// Capture arms sent, including arms whose sample was rejected.
    pub capture_attempts: usize,
    /// Samples the sensor asked to rescan.
    pub rejected_samples: usize,
    /// Whether the confirmation touch was accepted and the print bound.
    pub confirmed: bool,
}

impl EnrolStages {
    /// The number of stages a caller reports to `libfprint`, never above [`ENROL_STAGES`].
    pub fn completed(&self) -> usize {
        (self.accepted_samples + usize::from(self.confirmed)).min(ENROL_STAGES)
    }

    fn collecting(progress: EnrolProgress) -> Self {
        Self {
            accepted_samples: progress.accepted_samples,
            capture_attempts: progress.capture_attempts,
            rejected_samples: progress.rejected_samples,
            confirmed: false,
        }
    }
}

/// A bound print, the payload to store and the session it leaves open.
#[derive(Debug, PartialEq, Eq)]
pub struct BoundEnrolment {
    /// The 20-byte id the commit named (the sensor's enrolment id, or the last sample hash).
    pub template_id: [u8; crate::enrol::TEMPLATE_ID_LEN],
    /// Which id [`Self::template_id`] is.
    pub source: PrintSource,
    /// Samples the sensor accepted.
    pub accepted_samples: usize,
    /// The template handle the confirmation touch matched.
    pub match_id: u32,
    /// The fixed, versioned record to store on the `FpPrint`.
    pub payload: PrintPayload,
    /// The session, still open and usable for the next operation.
    pub session: Session,
}

impl BoundEnrolment {
    /// The payload's exact bytes, the [`PRINT_PAYLOAD_LEN`]-byte record stored on the print.
    pub fn payload_bytes(&self) -> [u8; PRINT_PAYLOAD_LEN] {
        self.payload.encode()
    }
}

/// Why an enrolment stored no print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// Collecting samples or the commit failed; the enrolment's own teardown has run.
    Enrol(EnrolError),
    /// The commit reply named no template handle, so nothing can be matched.
    NoCommitHandle,
    /// The confirmation capture or match failed; its own teardown has run.
    Confirmation(VerifyError),
    /// The confirmation answered, but not with a match for this print.
    ConfirmationRejected {
        /// The raw verdict word the sensor sent.
        word: u32,
        /// The handle the reply named, when it named one.
        matched_handle: Option<u32>,
        /// The handle the commit reply named and the confirmation asked about.
        expected_handle: u32,
        /// The raw wrapped reply length, for the diagnostic message.
        reply_len: usize,
    },
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl BindError {
    /// Whether a template may exist on the sensor because the commit was attempted.
    ///
    /// True for every failure after [`Enrol`] returned and for an [`EnrolError`] that itself says
    /// the commit was attempted; a finished operation reports `false`.
    pub fn may_have_stored_template(&self) -> bool {
        match self {
            Self::Enrol(error) => error.may_have_stored_template(),
            // An unexpected event is conservatively treated as "the commit may have run"; a
            // finished operation never sent anything.
            Self::UnexpectedEvent => true,
            Self::AlreadyFinished => false,
            Self::NoCommitHandle | Self::Confirmation(_) | Self::ConfirmationRejected { .. } => {
                true
            }
        }
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enrol(error) => {
                write!(f, "{error}")?;
                // A cancelled enrolment must say the same about the sensor as every other failure
                // after the commit: the template may remain and cannot be identified or removed.
                if matches!(error, EnrolError::Cancelled { .. }) {
                    write!(f, "; {TEMPLATE_MAY_REMAIN}")?;
                }
                Ok(())
            }
            Self::NoCommitHandle => write!(
                f,
                "the 0x6e commit reply named no template handle, so the print cannot be bound; \
                 {TEMPLATE_MAY_REMAIN}"
            ),
            Self::Confirmation(error) => write!(
                f,
                "the confirmation touch failed: {error}; {TEMPLATE_MAY_REMAIN}"
            ),
            Self::ConfirmationRejected {
                word,
                matched_handle,
                expected_handle,
                reply_len,
            } => {
                write!(
                    f,
                    "the confirmation touch did not match the committed template: verdict word \
                     {word}, matched handle {}, expected {expected_handle:#010x}, raw reply \
                     {reply_len} bytes; {TEMPLATE_MAY_REMAIN}",
                    match matched_handle {
                        Some(handle) => format!("{handle:#010x}"),
                        None => "absent".to_owned(),
                    }
                )
            }
            Self::UnexpectedEvent => f.write_str("unexpected event during enrolment"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for BindError {}

/// A failed enrolment: the reason and, when it survived, the still-open session.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrolFailure {
    /// Why the print was not stored.
    pub error: BindError,
    /// The session, when the failure did not require tearing it down.
    pub session: Option<Session>,
}

impl fmt::Display for EnrolFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error.to_string())
    }
}

impl std::error::Error for EnrolFailure {}

type BindOutcome = Result<BoundEnrolment, EnrolFailure>;

enum BindState {
    NotStarted,
    /// The sample collection and commit own the session until they finish.
    Collecting(Enrol),
    /// The confirmation owns the session; the bound record is built when it answers.
    Confirming {
        verify: Verify,
        template_id: [u8; crate::enrol::TEMPLATE_ID_LEN],
        source: PrintSource,
        handle: u32,
    },
    Done,
}

/// A whole enrolment: [`Enrol`] followed by one confirmation touch and its binding check.
///
/// The caller supplies the enrolment's base IV and the two IVs the confirmation needs (its capture
/// arm and its match request); the core generates no randomness. On success it returns the bound
/// payload and the still-open session. See the module docs for what a failure returns.
pub struct EnrolAndBind {
    session: Option<Session>,
    enrol_iv: [u8; crypto::BLOCK_LEN],
    confirmation_capture_iv: [u8; crypto::BLOCK_LEN],
    match_iv: [u8; crypto::BLOCK_LEN],
    state: BindState,
    stages: EnrolStages,
}

impl EnrolAndBind {
    /// Builds the enrolment for a live session.
    pub fn new(
        session: Session,
        enrol_iv: [u8; crypto::BLOCK_LEN],
        confirmation_capture_iv: [u8; crypto::BLOCK_LEN],
        match_iv: [u8; crypto::BLOCK_LEN],
    ) -> Self {
        Self {
            session: Some(session),
            enrol_iv,
            confirmation_capture_iv,
            match_iv,
            state: BindState::NotStarted,
            stages: EnrolStages::default(),
        }
    }

    /// How far the run has got, updated after every step.
    pub fn stages(&self) -> EnrolStages {
        self.stages
    }

    fn finish(&mut self, outcome: BindOutcome) -> Action<BindOutcome> {
        self.state = BindState::Done;
        Action::Finish(outcome)
    }

    fn failure(&mut self, error: BindError, session: Option<Session>) -> Action<BindOutcome> {
        self.finish(Err(EnrolFailure { error, session }))
    }

    /// Mirrors the inner operation's progress, then returns its action unchanged.
    fn advance_collecting(
        &mut self,
        action: Action<Result<EnrolledTemplate, EnrolError>>,
    ) -> Action<BindOutcome> {
        if let BindState::Collecting(enrol) = &self.state {
            self.stages = EnrolStages::collecting(enrol.progress());
        }
        match action {
            Action::Send(frame) => Action::Send(frame),
            Action::WaitFinger => Action::WaitFinger,
            Action::Finish(result) => self.start_confirmation(result),
        }
    }

    fn start_confirmation(
        &mut self,
        result: Result<EnrolledTemplate, EnrolError>,
    ) -> Action<BindOutcome> {
        let template = match result {
            Ok(template) => template,
            // The enrolment tore its session down; there is nothing to hand back.
            Err(error) => return self.failure(BindError::Enrol(error), None),
        };
        let Some(handle) = template.handle else {
            // A committed template the sensor did not name cannot be matched. The session is
            // still valid, so the caller can reuse it for the next operation.
            return self.failure(BindError::NoCommitHandle, Some(template.session));
        };
        let source = print_source(template.source);
        let verify = Verify::new(
            template.session,
            self.confirmation_capture_iv,
            self.match_iv,
        )
        .with_template_handle(handle)
        .with_command(cmd::IDENTIFY_HANDLES);
        self.state = BindState::Confirming {
            verify,
            template_id: template.template_id,
            source,
            handle,
        };
        let action = match &mut self.state {
            BindState::Confirming { verify, .. } => verify.start(),
            _ => unreachable!("the state was just set"),
        };
        self.advance_confirming(action)
    }

    fn advance_confirming(
        &mut self,
        action: Action<Result<crate::verify::Verification, VerifyError>>,
    ) -> Action<BindOutcome> {
        match action {
            Action::Send(frame) => Action::Send(frame),
            Action::WaitFinger => Action::WaitFinger,
            Action::Finish(result) => self.on_confirmed(result),
        }
    }

    fn on_confirmed(
        &mut self,
        result: Result<crate::verify::Verification, VerifyError>,
    ) -> Action<BindOutcome> {
        let (template_id, source, handle) = match &self.state {
            BindState::Confirming {
                template_id,
                source,
                handle,
                ..
            } => (*template_id, *source, *handle),
            _ => {
                return self.finish(Err(EnrolFailure {
                    error: BindError::AlreadyFinished,
                    session: None,
                }));
            }
        };
        match result {
            Ok(crate::verify::Verification { verdict, session }) => {
                let payload = PrintPayload::bound(template_id, source, handle);
                if payload.accepts(&verdict) {
                    self.stages.confirmed = true;
                    let accepted_samples = self.stages.accepted_samples;
                    return self.finish(Ok(BoundEnrolment {
                        template_id,
                        source,
                        accepted_samples,
                        match_id: handle,
                        payload,
                        session,
                    }));
                }
                self.reject_confirmation(&verdict, session)
            }
            // The confirmation's own teardown has run; its session is gone.
            Err(error) => self.failure(BindError::Confirmation(error), None),
        }
    }

    fn reject_confirmation(&mut self, verdict: &Verdict, session: Session) -> Action<BindOutcome> {
        let expected_handle = match &self.state {
            BindState::Confirming { handle, .. } => *handle,
            _ => 0,
        };
        self.failure(
            BindError::ConfirmationRejected {
                word: verdict.word,
                matched_handle: verdict.matched_handle,
                expected_handle,
                reply_len: verdict.reply_len,
            },
            Some(session),
        )
    }
}

impl Operation for EnrolAndBind {
    type Output = BindOutcome;

    fn start(&mut self) -> Action<BindOutcome> {
        if !matches!(self.state, BindState::NotStarted) {
            return self.finish(Err(EnrolFailure {
                error: BindError::AlreadyFinished,
                session: None,
            }));
        }
        let Some(session) = self.session.take() else {
            return self.finish(Err(EnrolFailure {
                error: BindError::AlreadyFinished,
                session: None,
            }));
        };
        self.state = BindState::Collecting(Enrol::new(session, self.enrol_iv));
        let action = match &mut self.state {
            BindState::Collecting(enrol) => enrol.start(),
            _ => unreachable!("the state was just set"),
        };
        self.advance_collecting(action)
    }

    fn step(&mut self, event: Event) -> Action<BindOutcome> {
        match std::mem::replace(&mut self.state, BindState::Done) {
            BindState::NotStarted => self.finish(Err(EnrolFailure {
                error: BindError::UnexpectedEvent,
                session: None,
            })),
            BindState::Collecting(mut enrol) => {
                let action = enrol.step(event);
                self.state = BindState::Collecting(enrol);
                self.advance_collecting(action)
            }
            BindState::Confirming {
                mut verify,
                template_id,
                source,
                handle,
            } => {
                let action = verify.step(event);
                self.state = BindState::Confirming {
                    verify,
                    template_id,
                    source,
                    handle,
                };
                self.advance_confirming(action)
            }
            BindState::Done => self.finish(Err(EnrolFailure {
                error: BindError::AlreadyFinished,
                session: None,
            })),
        }
    }
}

fn print_source(source: crate::enrol::TemplateSource) -> PrintSource {
    match source {
        crate::enrol::TemplateSource::EnrolmentId => PrintSource::EnrolmentId,
        crate::enrol::TemplateSource::SampleHash
        | crate::enrol::TemplateSource::ForcedSampleHash => PrintSource::SampleHash,
    }
}

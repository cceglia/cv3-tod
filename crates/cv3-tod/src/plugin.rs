//! The plugin's session state machine: open, keep, close.
//!
//! This is the safe half of the C boundary. It owns every piece of protocol state — the handshake,
//! the wrapped `0x02` open, the live [`Session`] and its key — and hands out one
//! [`Transfer`](cv3_wire::Transfer) at a time. The C shim performs that transfer with `libfprint`'s
//! asynchronous USB API and returns the result; it never parses a frame, computes a length or keeps
//! a session.
//!
//! Opening is two operations over one wire sequence: the `0x23`/`0x24` handshake, then the wrapped
//! `0x02` open. A failure after the sensor has allocated a handle makes the core send the plain
//! `0x04` close before it reports the failure, so no handle is left behind; a failure before that
//! has nothing to release. Closing sends `0x04` once and always reports success: the sensor's
//! answer cannot fail the close, and even a transport failure is logged and followed by the
//! interface release the shim performs.
//!
//! No operation here blocks. [`Plugin::open_start`], [`Plugin::on_transfer`] and
//! [`Plugin::close_start`] each return the next transfer or the final outcome, and every transfer
//! carries the core's own timeout.

use std::collections::VecDeque;

use cv3_core::bind::{
    BindError, BoundEnrolment, ENROL_STAGES, EnrolAndBind, EnrolFailure, EnrolStages,
};
use cv3_core::capture::CaptureError;
use cv3_core::enrol::EnrolError;
use cv3_core::event::{Action, TransportError};
use cv3_core::handshake::{Handshake, HandshakeError};
use cv3_core::operation::Operation;
use cv3_core::print::PRINT_PAYLOAD_LEN;
use cv3_core::session::{CloseError, CloseSession, OpenError, OpenSession, Session};
use cv3_core::verify::{MatchError, VerifyError};
use cv3_wire::{
    Exchange, FingerWait, IoFailure, IoReply, Transfer, event_from_finger, event_from_outcome,
};

use crate::secret::{EnrolIvs, Secrets};

/// What the shim should tell `libfprint` when an operation ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OutcomeKind {
    /// The operation succeeded.
    Ok = 0,
    /// Anything that is not more specific.
    General = 1,
    /// The sensor refused or answered with something this driver does not accept.
    Proto = 2,
    /// The device or its interface is held elsewhere.
    Busy = 3,
    /// The sensor left the bus.
    Removed = 4,
}

/// One finished open or close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub kind: OutcomeKind,
    /// The text `libfprint` reports, or — for a close that succeeded after a transfer failure — the
    /// text the shim logs.
    pub message: String,
}

impl Outcome {
    fn ok() -> Self {
        Self {
            kind: OutcomeKind::Ok,
            message: String::new(),
        }
    }

    fn error(kind: OutcomeKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// One step of an operation: perform this transfer, or report this outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Transfer(Transfer),
    Finished(Outcome),
}

impl Step {
    fn transfer(transfer: Transfer) -> Self {
        Self::Transfer(transfer)
    }
}

/// One progress report the shim has not collected yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Completed stages, never above [`ENROL_STAGES`].
    pub completed: usize,
    /// Whether this is a rejected sample the client should retry rather than an accepted stage.
    pub retry: bool,
}

/// Which progress a snapshot has already reported, so no stage is reported twice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Reported {
    accepted: usize,
    rejected: usize,
    confirmed: bool,
}

/// Where one core operation stopped during a step.
enum FlowStep<T> {
    Transfer(Transfer),
    Finished {
        output: T,
        /// The last transport failure seen during this operation, if any. The core carries the
        /// failure too, but only this record says whether it was a timeout, a disconnect or a busy
        /// device, which is what selects the `libfprint` error.
        failure: Option<IoFailure>,
    },
    Unsupported,
}

/// Drives one core [`Operation`] over the shared wire exchange, one transfer per step.
///
/// A wait for the finger is handled here too: [`FingerWait`] is the cancellable interrupt read and
/// answers the sensor's host timestamp requests like the command exchange does. Every other
/// operation completes without ever waiting; for those the branch is unreachable.
struct Flow<O: Operation> {
    operation: O,
    exchange: Option<Exchange>,
    finger: Option<FingerWait>,
    failure: Option<IoFailure>,
}

impl<O: Operation> Flow<O> {
    fn new(operation: O) -> Self {
        Self {
            operation,
            exchange: None,
            finger: None,
            failure: None,
        }
    }

    fn operation(&self) -> &O {
        &self.operation
    }

    fn start(&mut self) -> FlowStep<O::Output> {
        let action = self.operation.start();
        self.advance(action)
    }

    fn on_io_result(&mut self, reply: IoReply) -> FlowStep<O::Output> {
        if self.finger.is_some() {
            if let IoReply::Failed(failure) = &reply {
                self.failure = Some(failure.clone());
            }
            if let Some(finger) = self.finger.as_mut() {
                finger.on_io_result(reply);
            }
            return self.next_finger();
        }
        let Some(exchange) = self.exchange.as_mut() else {
            return FlowStep::Unsupported;
        };
        if let IoReply::Failed(failure) = &reply {
            self.failure = Some(failure.clone());
        }
        exchange.on_io_result(reply);
        self.next()
    }

    fn advance(&mut self, action: Action<O::Output>) -> FlowStep<O::Output> {
        match action {
            Action::Send(frame) => {
                self.finger = None;
                self.exchange = Some(Exchange::new(frame));
                self.next()
            }
            Action::WaitFinger => {
                self.exchange = None;
                self.finger = Some(FingerWait::new());
                self.next_finger()
            }
            Action::Finish(output) => FlowStep::Finished {
                output,
                failure: self.failure.take(),
            },
        }
    }

    fn next(&mut self) -> FlowStep<O::Output> {
        let Some(exchange) = self.exchange.as_mut() else {
            return FlowStep::Unsupported;
        };
        if let Some(transfer) = exchange.next_transfer() {
            return FlowStep::Transfer(transfer);
        }
        let outcome = exchange
            .outcome()
            .expect("an exchange with no transfer left has finished");
        self.exchange = None;
        let action = self.operation.step(event_from_outcome(outcome));
        self.advance(action)
    }

    fn next_finger(&mut self) -> FlowStep<O::Output> {
        let Some(finger) = self.finger.as_mut() else {
            return FlowStep::Unsupported;
        };
        if let Some(transfer) = finger.next_transfer() {
            return FlowStep::Transfer(transfer);
        }
        let outcome = finger
            .outcome()
            .expect("a finger wait with no transfer left has finished");
        self.finger = None;
        let action = self.operation.step(event_from_finger(outcome));
        self.advance(action)
    }
}

enum OpenState {
    Handshake(Flow<Handshake>),
    Open(Flow<OpenSession>),
    Done,
}

enum OpenStep {
    Transfer(Transfer),
    Opened(Session),
    Failed(Outcome),
}

/// One open: the handshake, then the wrapped `0x02`.
struct OpenRun {
    state: OpenState,
    open_iv: [u8; cv3_core::crypto::BLOCK_LEN],
}

impl OpenRun {
    fn new(secrets: Secrets) -> Self {
        let operation = Handshake::new(secrets.client_nonce, secrets.host_key, secrets.host_nonce)
            .keeping_handle();
        Self {
            state: OpenState::Handshake(Flow::new(operation)),
            open_iv: secrets.open_iv,
        }
    }

    fn start(&mut self) -> OpenStep {
        let state = std::mem::replace(&mut self.state, OpenState::Done);
        match state {
            OpenState::Handshake(mut flow) => {
                let step = flow.start();
                self.state = OpenState::Handshake(flow);
                self.after_handshake(step)
            }
            OpenState::Open(mut flow) => {
                let step = flow.start();
                self.state = OpenState::Open(flow);
                self.after_open(step)
            }
            OpenState::Done => already_finished(),
        }
    }

    fn on_io_result(&mut self, reply: IoReply) -> OpenStep {
        let state = std::mem::replace(&mut self.state, OpenState::Done);
        match state {
            OpenState::Handshake(mut flow) => {
                let step = flow.on_io_result(reply);
                self.state = OpenState::Handshake(flow);
                self.after_handshake(step)
            }
            OpenState::Open(mut flow) => {
                let step = flow.on_io_result(reply);
                self.state = OpenState::Open(flow);
                self.after_open(step)
            }
            OpenState::Done => already_finished(),
        }
    }

    fn after_handshake(&mut self, step: FlowStep<Result<Session, HandshakeError>>) -> OpenStep {
        match step {
            FlowStep::Transfer(transfer) => OpenStep::Transfer(transfer),
            FlowStep::Unsupported => {
                self.state = OpenState::Done;
                OpenStep::Failed(Outcome::error(
                    OutcomeKind::General,
                    "cv3: the handshake asked for a finger wait",
                ))
            }
            FlowStep::Finished { output, failure } => match output {
                Ok(session) => {
                    let mut flow = Flow::new(OpenSession::new(session, self.open_iv));
                    let step = flow.start();
                    self.state = OpenState::Open(flow);
                    self.after_open(step)
                }
                Err(error) => {
                    self.state = OpenState::Done;
                    OpenStep::Failed(outcome_from_handshake(&error, failure))
                }
            },
        }
    }

    fn after_open(&mut self, step: FlowStep<Result<Session, OpenError>>) -> OpenStep {
        match step {
            FlowStep::Transfer(transfer) => OpenStep::Transfer(transfer),
            FlowStep::Unsupported => {
                self.state = OpenState::Done;
                OpenStep::Failed(Outcome::error(
                    OutcomeKind::General,
                    "cv3: opening the session asked for a finger wait",
                ))
            }
            FlowStep::Finished { output, failure } => match output {
                Ok(session) => {
                    self.state = OpenState::Done;
                    OpenStep::Opened(session)
                }
                Err(error) => {
                    self.state = OpenState::Done;
                    OpenStep::Failed(outcome_from_open(&error, failure))
                }
            },
        }
    }
}

enum CloseStep {
    Transfer(Transfer),
    Finished(Option<String>),
}

/// One close: the plain `0x04` and nothing else.
struct CloseRun {
    flow: Flow<CloseSession>,
}

impl CloseRun {
    fn new(handle: u32) -> Self {
        Self {
            flow: Flow::new(CloseSession::new(handle)),
        }
    }

    fn start(&mut self) -> CloseStep {
        Self::classify(self.flow.start())
    }

    fn on_io_result(&mut self, reply: IoReply) -> CloseStep {
        Self::classify(self.flow.on_io_result(reply))
    }

    /// A close is always a success; a transport failure becomes the text the shim logs.
    fn classify(step: FlowStep<Result<(), CloseError>>) -> CloseStep {
        match step {
            FlowStep::Transfer(transfer) => CloseStep::Transfer(transfer),
            FlowStep::Unsupported => CloseStep::Finished(Some(
                "cv3: closing the session asked for a finger wait".to_owned(),
            )),
            FlowStep::Finished { output: Ok(()), .. } => CloseStep::Finished(None),
            FlowStep::Finished {
                output: Err(error), ..
            } => CloseStep::Finished(Some(format!("cv3: closing the session failed: {error}"))),
        }
    }
}

enum Job {
    Idle,
    Opening(Box<OpenRun>),
    /// A live session, kept until the close releases its handle and zeroed key.
    Session(Session),
    Enrolling(Box<EnrolRun>),
    Closing(CloseRun),
    Finished,
}

/// One step of a whole enrolment: perform this transfer, or report the final outcome.
enum EnrolStep {
    Transfer(Transfer),
    Finished {
        output: Result<BoundEnrolment, EnrolFailure>,
        /// The last transport failure, which selects the `libfprint` error.
        failure: Option<IoFailure>,
    },
}

/// Drives a whole [`EnrolAndBind`] over the shared transfer machinery.
struct EnrolRun {
    flow: Flow<EnrolAndBind>,
}

impl EnrolRun {
    fn new(operation: EnrolAndBind) -> Self {
        Self {
            flow: Flow::new(operation),
        }
    }

    fn stages(&self) -> EnrolStages {
        self.flow.operation().stages()
    }

    fn start(&mut self) -> EnrolStep {
        Self::classify(self.flow.start())
    }

    fn on_io_result(&mut self, reply: IoReply) -> EnrolStep {
        Self::classify(self.flow.on_io_result(reply))
    }

    fn classify(step: FlowStep<Result<BoundEnrolment, EnrolFailure>>) -> EnrolStep {
        match step {
            FlowStep::Transfer(transfer) => EnrolStep::Transfer(transfer),
            FlowStep::Finished { output, failure } => EnrolStep::Finished { output, failure },
            // A whole enrolment asks for the finger wait, which `Flow` performs; this cannot
            // happen, and reporting it beats panicking inside fprintd.
            FlowStep::Unsupported => EnrolStep::Finished {
                output: Err(EnrolFailure {
                    error: BindError::UnexpectedEvent,
                    session: None,
                }),
                failure: None,
            },
        }
    }
}

/// The whole plugin-side session state for one device.
///
/// One instance lives per `FpDevice` instance, owned by the shim. It starts idle; after a successful
/// open it holds the session; a failed open leaves it finished, and the shim destroys it and creates
/// a fresh one for the next claim.
pub struct Plugin {
    job: Job,
    /// Progress the shim has not collected yet, oldest first.
    progress: VecDeque<Progress>,
    /// What the last stage snapshot already reported, so no stage is reported twice.
    reported: Reported,
    /// The bound payload of the last successful enrolment, until the shim takes it.
    payload: Option<[u8; PRINT_PAYLOAD_LEN]>,
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            job: Job::Idle,
            progress: VecDeque::new(),
            reported: Reported::default(),
            payload: None,
        }
    }

    /// Starts the handshake and returns the first transfer.
    pub fn open_start(&mut self) -> Step {
        match Secrets::generate() {
            Ok(secrets) => self.open_start_with(secrets),
            Err(error) => Step::Finished(Outcome::error(
                OutcomeKind::General,
                format!("cv3: cannot open the sensor: {error}"),
            )),
        }
    }

    /// Starts an open with the given key material. Test support for a deterministic session.
    pub fn open_start_with(&mut self, secrets: Secrets) -> Step {
        if !matches!(self.job, Job::Idle | Job::Finished) {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: another open or close is already in progress",
            ));
        }
        let mut run = OpenRun::new(secrets);
        let step = run.start();
        self.after_open_step(run, step)
    }

    /// Consumes the result of the last transfer and returns the next step.
    pub fn on_transfer(&mut self, reply: IoReply) -> Step {
        match std::mem::replace(&mut self.job, Job::Finished) {
            Job::Opening(mut run) => {
                let step = run.on_io_result(reply);
                self.after_open_step(*run, step)
            }
            Job::Enrolling(mut run) => {
                let step = run.on_io_result(reply);
                self.after_enrol_step(*run, step)
            }
            Job::Closing(mut run) => {
                let step = run.on_io_result(reply);
                self.after_close_step(run, step)
            }
            other => {
                self.job = other;
                Step::Finished(Outcome::error(
                    OutcomeKind::General,
                    "cv3: a transfer completed with no operation in progress",
                ))
            }
        }
    }

    /// Starts a whole enrolment on the live session and returns the first transfer.
    ///
    /// The session must already be open: enrolment uses the session the open left behind and never
    /// opens or closes one itself.
    pub fn enrol_start(&mut self) -> Step {
        match EnrolIvs::generate() {
            Ok(ivs) => self.enrol_start_with(ivs),
            Err(error) => Step::Finished(Outcome::error(
                OutcomeKind::General,
                format!("cv3: cannot start the enrolment: {error}"),
            )),
        }
    }

    /// Starts an enrolment with the given IVs. Test support for a deterministic run.
    pub fn enrol_start_with(&mut self, ivs: EnrolIvs) -> Step {
        if !matches!(self.job, Job::Session(_)) {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: enrolment needs an open sensor session",
            ));
        }
        let Job::Session(session) = std::mem::replace(&mut self.job, Job::Finished) else {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: enrolment needs an open sensor session",
            ));
        };
        self.progress.clear();
        self.reported = Reported::default();
        self.payload = None;
        let mut run = EnrolRun::new(EnrolAndBind::new(
            session,
            ivs.enrol,
            ivs.confirmation_capture,
            ivs.matching,
        ));
        let step = run.start();
        self.after_enrol_step(run, step)
    }

    /// The next progress report the shim should hand to `libfprint`, oldest first.
    pub fn take_progress(&mut self) -> Option<Progress> {
        self.progress.pop_front()
    }

    /// The bound payload of a completed enrolment, once.
    pub fn take_payload(&mut self) -> Option<[u8; PRINT_PAYLOAD_LEN]> {
        self.payload.take()
    }

    /// Releases a live session and returns the `0x04` transfer, or finishes at once when there is
    /// no session (closing twice is harmless).
    pub fn close_start(&mut self) -> Step {
        match std::mem::replace(&mut self.job, Job::Finished) {
            Job::Session(session) => {
                let handle = session.handle;
                // Dropping the session zeroes its key; nothing else retains a copy.
                drop(session);
                let mut run = CloseRun::new(handle);
                let step = run.start();
                self.after_close_step(run, step)
            }
            Job::Idle | Job::Finished => {
                self.job = Job::Finished;
                Step::Finished(Outcome::ok())
            }
            Job::Opening(_) | Job::Closing(_) => {
                self.job = Job::Finished;
                Step::Finished(Outcome {
                    kind: OutcomeKind::Ok,
                    message: "cv3: close requested with no completed session".to_owned(),
                })
            }
            Job::Enrolling(_) => {
                self.job = Job::Finished;
                Step::Finished(Outcome {
                    kind: OutcomeKind::Ok,
                    message: "cv3: close requested during an enrolment".to_owned(),
                })
            }
        }
    }

    fn after_open_step(&mut self, run: OpenRun, step: OpenStep) -> Step {
        match step {
            OpenStep::Transfer(transfer) => {
                self.job = Job::Opening(Box::new(run));
                Step::transfer(transfer)
            }
            OpenStep::Opened(session) => {
                self.job = Job::Session(session);
                Step::Finished(Outcome::ok())
            }
            OpenStep::Failed(outcome) => {
                self.job = Job::Finished;
                Step::Finished(outcome)
            }
        }
    }

    fn after_close_step(&mut self, run: CloseRun, step: CloseStep) -> Step {
        match step {
            CloseStep::Transfer(transfer) => {
                self.job = Job::Closing(run);
                Step::transfer(transfer)
            }
            CloseStep::Finished(message) => {
                self.job = Job::Finished;
                Step::Finished(Outcome {
                    kind: OutcomeKind::Ok,
                    message: message.unwrap_or_default(),
                })
            }
        }
    }

    fn after_enrol_step(&mut self, run: EnrolRun, step: EnrolStep) -> Step {
        self.note_stages(run.stages());
        match step {
            EnrolStep::Transfer(transfer) => {
                self.job = Job::Enrolling(Box::new(run));
                Step::transfer(transfer)
            }
            EnrolStep::Finished {
                output,
                failure: io_failure,
            } => match output {
                Ok(bound) => {
                    self.payload = Some(bound.payload_bytes());
                    // The session stays open and usable for the next operation.
                    self.job = Job::Session(bound.session);
                    Step::Finished(Outcome::ok())
                }
                Err(failure) => {
                    let outcome = outcome_from_bind(&failure, io_failure);
                    self.job = match failure.session {
                        Some(session) => Job::Session(session),
                        None => Job::Finished,
                    };
                    Step::Finished(outcome)
                }
            },
        }
    }

    /// Records every stage or rejected sample a new snapshot reports, once.
    fn note_stages(&mut self, stages: EnrolStages) {
        while self.reported.accepted < stages.accepted_samples {
            self.reported.accepted += 1;
            self.progress.push_back(Progress {
                completed: self.reported.accepted.min(ENROL_STAGES),
                retry: false,
            });
        }
        while self.reported.rejected < stages.rejected_samples {
            self.reported.rejected += 1;
            self.progress.push_back(Progress {
                completed: self.reported.accepted.min(ENROL_STAGES),
                retry: true,
            });
        }
        if stages.confirmed && !self.reported.confirmed {
            self.reported.confirmed = true;
            self.progress.push_back(Progress {
                completed: (self.reported.accepted + 1).min(ENROL_STAGES),
                retry: false,
            });
        }
    }
}

fn outcome_from_handshake(error: &HandshakeError, failure: Option<IoFailure>) -> Outcome {
    match error {
        HandshakeError::Transport(transport) => transport_outcome(transport, failure),
        HandshakeError::RejectedChallenge(_)
        | HandshakeError::RejectedResponse(_)
        | HandshakeError::ShortReply { .. }
        | HandshakeError::MalformedFrame(_)
        | HandshakeError::InvalidDeviceKey => Outcome::error(
            OutcomeKind::Proto,
            format!("cv3: opening the sensor failed: {error}"),
        ),
        HandshakeError::Cancelled
        | HandshakeError::UnexpectedEvent
        | HandshakeError::AlreadyFinished => Outcome::error(
            OutcomeKind::General,
            format!("cv3: opening the sensor failed: {error}"),
        ),
    }
}

fn outcome_from_open(error: &OpenError, failure: Option<IoFailure>) -> Outcome {
    match error {
        OpenError::Transport(transport) => transport_outcome(transport, failure),
        OpenError::WrongSequence
        | OpenError::SensorStatus(_)
        | OpenError::MissingReply
        | OpenError::MalformedReply(_) => Outcome::error(
            OutcomeKind::Proto,
            format!("cv3: opening the session failed: {error}"),
        ),
        OpenError::Build(_)
        | OpenError::Cancelled
        | OpenError::UnexpectedEvent
        | OpenError::AlreadyFinished => Outcome::error(
            OutcomeKind::General,
            format!("cv3: opening the session failed: {error}"),
        ),
    }
}

/// Selects the error `libfprint` reports from the transfer failure the operation saw.
fn transport_outcome(error: &TransportError, failure: Option<IoFailure>) -> Outcome {
    let fallback = match error {
        TransportError::Disconnected => OutcomeKind::Removed,
        _ => OutcomeKind::General,
    };
    let kind = io_kind(failure, fallback);
    Outcome::error(kind, format!("cv3: opening the sensor failed: {error}"))
}

/// A disconnect is `REMOVED` and a busy sensor `BUSY`; anything else is general.
fn io_kind(failure: Option<IoFailure>, fallback: OutcomeKind) -> OutcomeKind {
    match failure {
        Some(IoFailure::Disconnected) => OutcomeKind::Removed,
        Some(IoFailure::Busy) => OutcomeKind::Busy,
        Some(_) => OutcomeKind::General,
        None => fallback,
    }
}

/// What `libfprint` is told when an enrolment stored no print.
fn outcome_from_bind(failure: &EnrolFailure, io: Option<IoFailure>) -> Outcome {
    Outcome::error(
        bind_kind(&failure.error, io),
        format!("cv3: enrolment failed: {}", failure.error),
    )
}

/// The `libfprint` error kind for an enrolment failure.
fn bind_kind(error: &BindError, io: Option<IoFailure>) -> OutcomeKind {
    let transport = match error {
        BindError::Enrol(EnrolError::Transport { error, .. }) => Some(error),
        BindError::Confirmation(VerifyError::Capture(CaptureError::Transport(error))) => {
            Some(error)
        }
        BindError::Confirmation(VerifyError::Match(MatchError::Transport(error))) => Some(error),
        _ => None,
    };
    if let Some(error) = transport {
        let fallback = match error {
            TransportError::Disconnected => OutcomeKind::Removed,
            _ => OutcomeKind::General,
        };
        return io_kind(io, fallback);
    }

    match error {
        // The sensor answered with something this driver does not accept, or a command it
        // refused: a protocol failure, not a general one.
        BindError::Enrol(
            EnrolError::MissingReply { .. }
            | EnrolError::UpdateRejected { .. }
            | EnrolError::Incomplete { .. }
            | EnrolError::CommitRejected { .. }
            | EnrolError::MalformedReply { .. }
            | EnrolError::MalformedFrame { .. },
        )
        | BindError::Confirmation(
            VerifyError::Capture(
                CaptureError::AlreadyPending
                | CaptureError::NoSampleHash
                | CaptureError::MissingReply
                | CaptureError::SensorStatus(_)
                | CaptureError::MalformedReply(_),
            )
            | VerifyError::Match(
                MatchError::WrongSequence
                | MatchError::SensorStatus { .. }
                | MatchError::MissingReply
                | MatchError::MissingVerdict { .. }
                | MatchError::MalformedReply(_),
            ),
        )
        | BindError::NoCommitHandle => OutcomeKind::Proto,
        BindError::Enrol(
            EnrolError::Build(_)
            | EnrolError::Capture(_)
            | EnrolError::AttemptLimit { .. }
            | EnrolError::Cancelled { .. }
            | EnrolError::UnexpectedEvent { .. }
            | EnrolError::AlreadyFinished,
        )
        | BindError::Confirmation(
            VerifyError::Capture(
                CaptureError::Build(_)
                | CaptureError::FingerTimeout
                | CaptureError::Cancelled
                | CaptureError::UnexpectedEvent
                | CaptureError::AlreadyFinished,
            )
            | VerifyError::Match(
                MatchError::Build(_)
                | MatchError::Cancelled
                | MatchError::UnexpectedEvent
                | MatchError::AlreadyFinished,
            )
            | VerifyError::UnexpectedEvent
            | VerifyError::AlreadyFinished,
        )
        | BindError::ConfirmationRejected { .. }
        | BindError::UnexpectedEvent
        | BindError::AlreadyFinished => OutcomeKind::General,
        // The three transport shapes are classified above and never reach this match; naming them
        // keeps the match exhaustive when a variant is added.
        BindError::Enrol(EnrolError::Transport { .. })
        | BindError::Confirmation(VerifyError::Capture(CaptureError::Transport(_)))
        | BindError::Confirmation(VerifyError::Match(MatchError::Transport(_))) => {
            OutcomeKind::General
        }
    }
}

fn already_finished() -> OpenStep {
    OpenStep::Failed(Outcome::error(
        OutcomeKind::General,
        "cv3: the open has already finished",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use cv3_core::crypto::HostKey;
    use cv3_core::frame;
    use cv3_core::handshake::NONCE_LEN;
    use cv3_core::proto::{attr, cmd};

    const HANDLE: u32 = 0x1122_3344;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        let bytes: Vec<u8> = digits
            .chunks(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
                let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
                (high << 4) | low
            })
            .collect();
        assert_eq!(bytes.len(), N);
        bytes.try_into().expect("length checked")
    }

    fn secrets() -> Secrets {
        // RFC 5903 section 8.1's initiator scalar; a fixed IV keeps the frame bytes reproducible.
        Secrets {
            host_key: HostKey::from_bytes(&unhex::<32>(
                "c88f01f510d9ac3f70a292daa2316de5
                 44e9aab8afe84049c62a9c57862d1433",
            ))
            .expect("RFC scalar"),
            client_nonce: unhex::<NONCE_LEN>("404142434445464748494a4b4c4d4e4f50515253"),
            host_nonce: unhex::<NONCE_LEN>("202122232425262728292a2b2c2d2e2f30313233"),
            open_iv: [0x10; 16],
        }
    }

    fn device_public() -> [u8; 64] {
        unhex::<64>(
            "d12dfb5289c8d4f81208b70270398c34
             2296970a0bccb74c736fc7554494bf63
             56fbf3ca366cc23e8157854c13c58d6a
             ac23f046ada30f8353e74f33039872ab",
        )
    }

    fn challenge_reply(status: u32) -> Vec<u8> {
        let mut param = vec![0u8; 148];
        param[..64].copy_from_slice(&device_public());
        param[128..].copy_from_slice(&unhex::<20>("000102030405060708090a0b0c0d0e0f10111213"));
        frame::build_plain_reply(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, status, &param)
    }

    fn response_reply(status: u32) -> Vec<u8> {
        frame::build_plain_reply(
            cmd::CHALLENGE_RESPONSE,
            attr::CHALLENGE_RESPONSE,
            HANDLE,
            status,
            &[],
        )
    }

    fn open_reply(status: u32) -> Vec<u8> {
        frame::build_plain_reply(cmd::OPEN_SESSION, attr::SESSION, HANDLE, status, &[])
    }

    fn announcement(len: usize) -> IoReply {
        let mut bytes = vec![0u8; cv3_wire::ANNOUNCEMENT_LEN];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[4..].copy_from_slice(&(len as u32).to_le_bytes());
        IoReply::Data(bytes)
    }

    /// The three results one command with a body produces.
    fn reply(body: Vec<u8>) -> Vec<IoReply> {
        vec![
            IoReply::Completed,
            announcement(body.len()),
            IoReply::Data(body),
        ]
    }

    /// The two results one command with an empty reply produces.
    fn empty_reply() -> Vec<IoReply> {
        vec![IoReply::Completed, announcement(0)]
    }

    /// Runs a plugin step to completion against scripted transport results, recording every
    /// transfer it asked for.
    fn drive(
        plugin: &mut Plugin,
        first: Step,
        script: &mut VecDeque<IoReply>,
    ) -> (Step, Vec<Transfer>) {
        let mut transfers = Vec::new();
        let mut step = first;
        loop {
            match step {
                Step::Transfer(transfer) => {
                    transfers.push(transfer);
                    let next = script
                        .pop_front()
                        .unwrap_or_else(|| panic!("the script ran out of results"));
                    step = plugin.on_transfer(next);
                }
                finished => return (finished, transfers),
            }
        }
    }

    fn open_run(plugin: &mut Plugin, script: &mut VecDeque<IoReply>) -> (Step, Vec<Transfer>) {
        let first = plugin.open_start_with(secrets());
        drive(plugin, first, script)
    }

    fn close_run(plugin: &mut Plugin, script: &mut VecDeque<IoReply>) -> (Step, Vec<Transfer>) {
        let first = plugin.close_start();
        drive(plugin, first, script)
    }

    fn command_of(transfer: &Transfer) -> u16 {
        command_of_opt(transfer).expect("expected an OUT transfer")
    }

    fn command_of_opt(transfer: &Transfer) -> Option<u16> {
        match transfer {
            Transfer::Out { frame, .. } => Some(u16::from_le_bytes([frame[8], frame[9]])),
            _ => None,
        }
    }

    /// The last command frame the plugin asked to write.
    fn last_out(transfers: &[Transfer]) -> Option<u16> {
        transfers.iter().filter_map(command_of_opt).next_back()
    }

    #[test]
    fn a_successful_open_sends_the_handshake_then_the_wrapped_open() {
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();

        let (step, transfers) = open_run(&mut plugin, &mut script);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        let commands: Vec<u16> = transfers.iter().filter_map(command_of_opt).collect();
        assert_eq!(
            commands,
            [cmd::CHALLENGE, cmd::CHALLENGE_RESPONSE, cmd::OPEN_SESSION]
        );
        assert_eq!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::InterruptIn { .. }))
                .count(),
            3,
            "each command announces its reply"
        );
    }

    #[test]
    fn a_failed_open_releases_the_handle_before_it_reports_the_failure() {
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0x09)),
            empty_reply(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let (step, transfers) = open_run(&mut plugin, &mut script);

        let commands: Vec<u16> = transfers.iter().filter_map(command_of_opt).collect();
        assert_eq!(
            commands,
            [cmd::CHALLENGE, cmd::CHALLENGE_RESPONSE, cmd::CLOSE_SESSION],
            "the handle learned from 0x23 is released before the error"
        );
        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Proto);
                assert!(outcome.message.contains("0x09"), "{}", outcome.message);
                assert!(outcome.message.starts_with("cv3:"));
            }
            other => panic!("expected a finished open, got {other:?}"),
        }
    }

    #[test]
    fn a_second_open_after_a_failed_open_succeeds() {
        let mut plugin = Plugin::new();

        let mut failed: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0x09)),
            empty_reply(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let (step, _) = open_run(&mut plugin, &mut failed);
        assert!(matches!(step, Step::Finished(ref outcome) if outcome.kind == OutcomeKind::Proto));

        let mut succeeded: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let (step, _) = open_run(&mut plugin, &mut succeeded);
        assert_eq!(step, Step::Finished(Outcome::ok()));
    }

    #[test]
    fn a_failed_wrapped_open_releases_the_handle() {
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0x0c)),
            empty_reply(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let (step, transfers) = open_run(&mut plugin, &mut script);

        assert_eq!(last_out(&transfers).expect("a command"), cmd::CLOSE_SESSION);
        match step {
            Step::Finished(outcome) => assert_eq!(outcome.kind, OutcomeKind::Proto),
            other => panic!("expected a finished open, got {other:?}"),
        }
    }

    #[test]
    fn close_sends_the_plain_close_and_succeeds() {
        let mut plugin = Plugin::new();
        let mut open: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let (step, _) = open_run(&mut plugin, &mut open);
        assert_eq!(step, Step::Finished(Outcome::ok()));

        let mut close: VecDeque<IoReply> = empty_reply().into_iter().collect();
        let (step, transfers) = close_run(&mut plugin, &mut close);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(transfers.len(), 2, "one frame out, one announcement");
        assert_eq!(command_of(&transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn a_close_whose_transfer_fails_still_succeeds_with_a_message() {
        let mut plugin = Plugin::new();
        let mut open: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let _ = open_run(&mut plugin, &mut open);

        let mut close: VecDeque<IoReply> =
            [IoReply::Failed(IoFailure::Timeout)].into_iter().collect();
        let (step, _) = close_run(&mut plugin, &mut close);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Ok, "close always succeeds");
                assert!(outcome.message.contains("failed"), "{}", outcome.message);
            }
            other => panic!("expected a finished close, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_failure_at_each_open_stage_is_reported() {
        // Failure of the very first write: no handle exists, so nothing is released.
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> =
            [IoReply::Failed(IoFailure::Timeout)].into_iter().collect();
        let (step, transfers) = open_run(&mut plugin, &mut script);
        assert_eq!(transfers.len(), 1, "only the failed write");
        assert!(matches!(step, Step::Finished(ref o) if o.kind == OutcomeKind::General));

        // Failure of the announcement after the challenge was written.
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> =
            [IoReply::Completed, IoReply::Failed(IoFailure::Timeout)]
                .into_iter()
                .collect();
        let (step, _) = open_run(&mut plugin, &mut script);
        assert!(matches!(step, Step::Finished(ref o) if o.kind == OutcomeKind::General));

        // Failure of the 0x24 body after the handle was learned: the close frame must still be
        // sent, and the open reports the transport error.
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            vec![
                IoReply::Completed,
                announcement(44),
                IoReply::Failed(IoFailure::Stall),
            ],
            empty_reply(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let (step, transfers) = open_run(&mut plugin, &mut script);
        assert_eq!(last_out(&transfers).expect("a command"), cmd::CLOSE_SESSION);
        assert!(matches!(step, Step::Finished(ref o) if o.kind == OutcomeKind::General));

        // A body failure before the handle is known has nothing to release.
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            IoReply::Completed,
            announcement(192),
            IoReply::Failed(IoFailure::Stall),
        ]
        .into_iter()
        .collect();
        let (step, transfers) = open_run(&mut plugin, &mut script);
        assert!(
            transfers
                .iter()
                .all(|transfer| command_of_opt(transfer) != Some(cmd::CLOSE_SESSION)),
            "no handle was learned, so nothing is closed: {transfers:?}"
        );
        assert!(matches!(step, Step::Finished(ref o) if o.kind == OutcomeKind::General));
    }

    #[test]
    fn a_disconnect_is_reported_as_removed_and_a_busy_sensor_as_busy() {
        for (failure, kind) in [
            (IoFailure::Disconnected, OutcomeKind::Removed),
            (IoFailure::Busy, OutcomeKind::Busy),
        ] {
            let mut plugin = Plugin::new();
            let mut script: VecDeque<IoReply> = [IoReply::Failed(failure)].into_iter().collect();
            let (step, _) = open_run(&mut plugin, &mut script);
            assert!(
                matches!(step, Step::Finished(ref outcome) if outcome.kind == kind),
                "expected {kind:?}"
            );
        }
    }

    #[test]
    fn a_timestamp_request_during_the_handshake_is_answered_and_the_open_continues() {
        let mut plugin = Plugin::new();
        let mut script: VecDeque<IoReply> = [
            // 0x23 out; the sensor asks for the clock before announcing.
            vec![
                IoReply::Completed,
                IoReply::Data(5u32.to_le_bytes().to_vec()),
            ],
            // The control answer, then the real announcement and body.
            vec![
                IoReply::Completed,
                announcement(192),
                IoReply::Data(challenge_reply(0)),
            ],
            // 0x24 and the wrapped open.
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();

        let (step, transfers) = open_run(&mut plugin, &mut script);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        let control = transfers
            .iter()
            .find(|transfer| matches!(transfer, Transfer::ControlOut { .. }));
        let Some(Transfer::ControlOut {
            request,
            request_type,
            timeout_ms,
            ..
        }) = control
        else {
            panic!("no timestamp control transfer: {transfers:?}");
        };
        assert_eq!(*request, cv3_wire::timestamp::HOST_TIMESTAMP_REQUEST);
        assert_eq!(
            *request_type,
            cv3_wire::timestamp::HOST_TIMESTAMP_REQUEST_TYPE
        );
        assert_eq!(*timeout_ms, cv3_wire::timestamp::SYNC_TIMEOUT_MS);
        // The control answer is followed by another interrupt read, then the challenge body.
        let control_index = transfers
            .iter()
            .position(|transfer| matches!(transfer, Transfer::ControlOut { .. }))
            .expect("control");
        assert!(matches!(
            transfers[control_index + 1],
            Transfer::InterruptIn { .. }
        ));
    }

    #[test]
    fn closing_without_a_session_finishes_at_once() {
        let mut plugin = Plugin::new();
        assert_eq!(plugin.close_start(), Step::Finished(Outcome::ok()));
        assert_eq!(plugin.close_start(), Step::Finished(Outcome::ok()));
    }

    #[test]
    fn a_transfer_with_no_operation_is_an_error_not_a_panic() {
        let mut plugin = Plugin::new();
        assert!(matches!(
            plugin.on_transfer(IoReply::Completed),
            Step::Finished(Outcome {
                kind: OutcomeKind::General,
                ..
            })
        ));
    }

    // ---- Enrolment through the session ------------------------------------------------------

    use cv3_core::crypto::SESSION_KEY_LEN;
    use cv3_core::print::PRINT_PAYLOAD_LEN;
    use cv3_core::proto::status;
    use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
    use cv3_core::{Handshake, MAX_ACCEPTED_SAMPLES, OpenSession};

    use crate::secret::EnrolIvs;

    /// The enrolled template handle the scripted commit reply names.
    const COMMIT_HANDLE: u32 = 0x00f2_361f;
    const ENROLMENT_ID: [u8; 20] = [0xa5; 20];
    const SAMPLE_HASH: [u8; 20] = [0x5a; 20];

    /// The session key the plugin will derive: the handshake over the same fixed material.
    fn session_key() -> [u8; SESSION_KEY_LEN] {
        let mut transport = ScriptedTransport::default();
        transport.push(ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        });
        transport.push(ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        });
        let material = secrets();
        let mut handshake = Handshake::new(
            material.client_nonce,
            material.host_key,
            material.host_nonce,
        )
        .keeping_handle();
        let session = run(&mut handshake, &mut transport).expect("the fixtures open a session");
        transport.push(ScriptedOutcome::Reply {
            status: 0,
            body: open_reply(0),
        });
        let mut open = OpenSession::new(session, material.open_iv);
        let session = run(&mut open, &mut transport).expect("the wrapped open succeeds");
        *session.key().as_bytes()
    }

    fn wrapped_reply(
        key: &[u8; SESSION_KEY_LEN],
        command: u16,
        attribute: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        wrapped_reply_status(key, command, attribute, 0, plaintext)
    }

    /// The same frame with `status` at header offset 20, where the core reads the command status.
    fn wrapped_reply_status(
        key: &[u8; SESSION_KEY_LEN],
        command: u16,
        attribute: u8,
        status: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let iv = [0x30u8; 16];
        let ciphertext = cv3_core::crypto::encrypt_cbc(key, &iv, plaintext);
        let mut body = frame::build_wrapped(
            command,
            attribute,
            HANDLE,
            &iv,
            plaintext.len() as u32,
            &ciphertext,
        );
        body[20..24].copy_from_slice(&status.to_le_bytes());
        body
    }

    fn twenty_byte_tlv(value: &[u8; 20]) -> Vec<u8> {
        let mut plaintext = vec![0u8; 28];
        plaintext[4..8].copy_from_slice(&20u32.to_le_bytes());
        plaintext[8..].copy_from_slice(value);
        plaintext
    }

    fn sample_hash_plaintext() -> Vec<u8> {
        twenty_byte_tlv(&SAMPLE_HASH)
    }

    fn commit_plaintext(handle: u32) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&3u32.to_le_bytes());
        plaintext.extend_from_slice(&0u32.to_le_bytes());
        plaintext.extend_from_slice(&0u32.to_le_bytes());
        plaintext.extend_from_slice(&4u32.to_le_bytes());
        plaintext.extend_from_slice(&handle.to_le_bytes());
        plaintext
    }

    fn push_enrol_sample(
        script: &mut VecDeque<IoReply>,
        key: &[u8; SESSION_KEY_LEN],
        update_status: u32,
        template_id: Option<&[u8; 20]>,
    ) {
        script.extend(reply(wrapped_reply(
            key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        script.extend(reply(wrapped_reply_status(
            key,
            cmd::UPDATE_ENROLMENT,
            attr::SESSION,
            update_status,
            &twenty_byte_tlv(template_id.unwrap_or(&SAMPLE_HASH)),
        )));
    }

    fn push_enrol_commit(script: &mut VecDeque<IoReply>, key: &[u8; SESSION_KEY_LEN], body: &[u8]) {
        script.extend(reply(wrapped_reply(
            key,
            cmd::COMMIT_ENROLMENT,
            attr::SESSION,
            body,
        )));
    }

    fn push_confirmation(
        script: &mut VecDeque<IoReply>,
        key: &[u8; SESSION_KEY_LEN],
        word: u32,
        handle: u32,
    ) {
        script.extend(reply(wrapped_reply(
            key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        let mut plaintext = vec![0u8; 56];
        plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
        plaintext[8..12].copy_from_slice(&word.to_le_bytes());
        plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
        plaintext[20..24].copy_from_slice(&handle.to_le_bytes());
        script.extend(reply(wrapped_reply(
            key,
            cmd::IDENTIFY_HANDLES,
            attr::CAPTURE,
            &plaintext,
        )));
    }

    fn enroled_ivs() -> EnrolIvs {
        EnrolIvs {
            enrol: [0x40; 16],
            confirmation_capture: [0x60; 16],
            matching: [0x70; 16],
        }
    }

    /// Drives the enrolment, collecting every progress report the shim would hand to libfprint.
    fn drive_enrol(
        plugin: &mut Plugin,
        script: &mut VecDeque<IoReply>,
    ) -> (Step, Vec<Transfer>, Vec<Progress>) {
        let mut step = plugin.enrol_start_with(enroled_ivs());
        let mut transfers = Vec::new();
        let mut progress = Vec::new();
        loop {
            while let Some(report) = plugin.take_progress() {
                progress.push(report);
            }
            match step {
                Step::Transfer(transfer) => {
                    transfers.push(transfer);
                    let next = script
                        .pop_front()
                        .unwrap_or_else(|| panic!("the script ran out of results"));
                    step = plugin.on_transfer(next);
                }
                finished => {
                    while let Some(report) = plugin.take_progress() {
                        progress.push(report);
                    }
                    return (finished, transfers, progress);
                }
            }
        }
    }

    fn opened_plugin(script: &mut VecDeque<IoReply>) -> Plugin {
        let mut plugin = Plugin::new();
        let (step, _) = open_run(&mut plugin, script);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        plugin
    }

    fn enrol_script(key: &[u8; SESSION_KEY_LEN], samples: usize) -> VecDeque<IoReply> {
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            key,
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &[],
        )));
        script.extend(empty_reply());
        for sample in 0..samples {
            let completion =
                (samples < MAX_ACCEPTED_SAMPLES && sample + 1 == samples).then_some(&ENROLMENT_ID);
            push_enrol_sample(&mut script, key, status::SAMPLE_ACCEPTED, completion);
        }
        push_enrol_commit(&mut script, key, &commit_plaintext(COMMIT_HANDLE));
        push_confirmation(&mut script, key, 1, COMMIT_HANDLE);
        script
    }

    #[test]
    fn a_successful_enrolment_reports_every_stage_and_hands_back_the_bound_print() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = enrol_script(&key, 2);
        let (step, transfers, progress) = drive_enrol(&mut plugin, &mut enrol);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(
            progress,
            [
                Progress {
                    completed: 1,
                    retry: false
                },
                Progress {
                    completed: 2,
                    retry: false
                },
                Progress {
                    completed: 3,
                    retry: false
                },
            ],
            "two accepted samples and the confirmation are three stages"
        );

        let commands: Vec<u16> = transfers.iter().filter_map(command_of_opt).collect();
        assert_eq!(
            commands,
            [
                cmd::DISCARD_ENROLMENT,
                cmd::START_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::UPDATE_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::UPDATE_ENROLMENT,
                cmd::COMMIT_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::IDENTIFY_HANDLES,
            ]
        );
        assert_eq!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .count(),
            3,
            "one cancellable finger wait per sample and one for the confirmation"
        );
        assert!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .all(Transfer::cancellable),
        );

        let payload = plugin
            .take_payload()
            .expect("a successful enrolment hands out its payload");
        assert_eq!(payload.len(), PRINT_PAYLOAD_LEN);
        assert_eq!(&payload[..4], b"CV3P");
        assert_eq!(
            u32::from_le_bytes([payload[26], payload[27], payload[28], payload[29]]),
            COMMIT_HANDLE
        );
        assert_eq!(
            plugin.take_payload(),
            None,
            "the payload is handed out once"
        );

        // The session is still usable: the close writes the plain 0x04.
        let mut close = empty_reply().into_iter().collect();
        let (step, transfers) = close_run(&mut plugin, &mut close);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(command_of(&transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn a_rejected_sample_is_reported_as_a_retry_without_a_new_stage() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = VecDeque::new();
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &[],
        )));
        enrol.extend(empty_reply());
        push_enrol_sample(&mut enrol, &key, status::SAMPLE_ACCEPTED, None);
        push_enrol_sample(&mut enrol, &key, status::RESCAN_A, None);
        push_enrol_sample(
            &mut enrol,
            &key,
            status::SAMPLE_ACCEPTED,
            Some(&ENROLMENT_ID),
        );
        push_enrol_commit(&mut enrol, &key, &commit_plaintext(COMMIT_HANDLE));
        push_confirmation(&mut enrol, &key, 1, COMMIT_HANDLE);

        let (step, _, progress) = drive_enrol(&mut plugin, &mut enrol);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert!(
            progress.contains(&Progress {
                completed: 1,
                retry: true,
            }),
            "the rejected sample is a retry at the unchanged stage: {progress:?}"
        );
        let advanced = progress.iter().filter(|report| !report.retry).count();
        assert_eq!(advanced, 3, "two samples and the confirmation advance");
        assert!(progress.iter().all(|report| report.completed <= 13));
    }

    #[test]
    fn a_confirmation_that_does_not_match_fails_without_a_payload_and_keeps_the_session() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = enrol_script(&key, 1);
        // Replace the confirmation match with a no-match.
        enrol.truncate(enrol.len() - 7);
        push_confirmation(&mut enrol, &key, 0, 0);

        let (step, _, _) = drive_enrol(&mut plugin, &mut enrol);
        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::General);
                assert!(
                    outcome.message.contains("enrolment failed"),
                    "{}",
                    outcome.message
                );
                assert!(
                    outcome.message.contains("cannot identify or remove it yet"),
                    "the message names the remaining template: {}",
                    outcome.message
                );
            }
            other => panic!("expected a finished enrolment, got {other:?}"),
        }
        assert_eq!(plugin.take_payload(), None, "nothing is stored");

        // The session survived the refused confirmation.
        let mut close = empty_reply().into_iter().collect();
        let (step, transfers) = close_run(&mut plugin, &mut close);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(command_of(&transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn a_commit_without_a_handle_fails_and_keeps_the_session() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = VecDeque::new();
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &[],
        )));
        enrol.extend(empty_reply());
        push_enrol_sample(
            &mut enrol,
            &key,
            status::SAMPLE_ACCEPTED,
            Some(&ENROLMENT_ID),
        );
        push_enrol_commit(&mut enrol, &key, &[]);

        let (step, transfers, _) = drive_enrol(&mut plugin, &mut enrol);
        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Proto);
                assert!(outcome.message.contains("0x6e"), "{}", outcome.message);
                assert!(
                    outcome.message.contains("cannot identify or remove it yet"),
                    "{}",
                    outcome.message
                );
            }
            other => panic!("expected a finished enrolment, got {other:?}"),
        }
        assert!(
            !transfers
                .iter()
                .any(|transfer| command_of_opt(transfer) == Some(cmd::IDENTIFY_HANDLES))
        );
        assert_eq!(plugin.take_payload(), None);
    }

    #[test]
    fn a_cancelled_finger_wait_fails_without_a_payload_and_says_the_template_may_remain() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = VecDeque::new();
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &[],
        )));
        enrol.extend(empty_reply());
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        enrol.push_back(IoReply::Failed(IoFailure::Cancelled));
        // The capture's teardown: the sessionless cancel and the close.
        enrol.extend(empty_reply());
        enrol.extend(empty_reply());

        let (step, transfers, _) = drive_enrol(&mut plugin, &mut enrol);
        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::General);
                assert!(outcome.message.contains("cancelled"), "{}", outcome.message);
                assert!(
                    outcome.message.contains("cannot identify or remove it yet"),
                    "{}",
                    outcome.message
                );
            }
            other => panic!("expected a finished enrolment, got {other:?}"),
        }
        assert_eq!(plugin.take_payload(), None);
        assert_eq!(
            transfers
                .iter()
                .filter_map(command_of_opt)
                .collect::<Vec<_>>()
                .last(),
            Some(&cmd::CLOSE_SESSION),
            "the cancelled capture closed its handle"
        );

        // The failed enrolment already closed the session; closing again sends nothing.
        assert_eq!(plugin.close_start(), Step::Finished(Outcome::ok()));
    }

    #[test]
    fn a_timestamp_request_during_the_finger_wait_is_answered_and_the_read_retried() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = VecDeque::new();
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &[],
        )));
        enrol.extend(empty_reply());
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        // The sensor asks for the clock before delivering the finger event.
        enrol.push_back(IoReply::Data(
            cv3_wire::timestamp::HOST_TIMESTAMP_INTERRUPT
                .to_le_bytes()
                .to_vec(),
        ));
        enrol.push_back(IoReply::Completed);
        enrol.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        enrol.extend(reply(wrapped_reply_status(
            &key,
            cmd::UPDATE_ENROLMENT,
            attr::SESSION,
            status::OK,
            &twenty_byte_tlv(&ENROLMENT_ID),
        )));
        push_enrol_commit(&mut enrol, &key, &commit_plaintext(COMMIT_HANDLE));
        push_confirmation(&mut enrol, &key, 1, COMMIT_HANDLE);

        let (step, transfers, _) = drive_enrol(&mut plugin, &mut enrol);
        assert_eq!(step, Step::Finished(Outcome::ok()));

        let control = transfers
            .iter()
            .position(|transfer| matches!(transfer, Transfer::ControlOut { .. }))
            .expect("the timestamp request is answered");
        let Transfer::ControlOut {
            request,
            timeout_ms,
            ..
        } = &transfers[control]
        else {
            unreachable!()
        };
        assert_eq!(*request, cv3_wire::timestamp::HOST_TIMESTAMP_REQUEST);
        assert_eq!(*timeout_ms, cv3_wire::timestamp::SYNC_TIMEOUT_MS);
        assert!(!transfers[control].cancellable());
        assert!(matches!(transfers[control - 1], Transfer::FingerIn { .. }));
        assert!(matches!(transfers[control + 1], Transfer::FingerIn { .. }));
    }

    #[test]
    fn a_transfer_failure_at_each_enrolment_state_is_reported() {
        // The failure is injected at the discard, the start, the first arm, the update, the
        // commit, the confirmation arm and the confirmation match, in that order.
        for failure_at in 0..7 {
            let key = session_key();
            let mut script: VecDeque<IoReply> = [
                reply(challenge_reply(0)),
                reply(response_reply(0)),
                reply(open_reply(0)),
            ]
            .into_iter()
            .flatten()
            .collect();
            let mut plugin = opened_plugin(&mut script);

            let mut enrol = VecDeque::new();
            if failure_at == 0 {
                enrol.push_back(IoReply::Failed(IoFailure::Disconnected));
                enrol.extend(empty_reply());
                enrol.extend(empty_reply());
            } else {
                enrol.extend(reply(wrapped_reply(
                    &key,
                    cmd::DISCARD_ENROLMENT,
                    attr::SESSION,
                    &[],
                )));
                if failure_at == 1 {
                    enrol.push_back(IoReply::Failed(IoFailure::Stall));
                    enrol.extend(empty_reply());
                    enrol.extend(empty_reply());
                } else {
                    enrol.extend(empty_reply());
                    if failure_at == 2 {
                        enrol.push_back(IoReply::Failed(IoFailure::Timeout));
                        enrol.extend(empty_reply());
                        enrol.extend(empty_reply());
                    } else {
                        enrol.extend(reply(wrapped_reply(
                            &key,
                            cmd::ARM_CAPTURE,
                            attr::CAPTURE,
                            &sample_hash_plaintext(),
                        )));
                        enrol.push_back(IoReply::Data(
                            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
                        ));
                        if failure_at == 3 {
                            enrol.push_back(IoReply::Failed(IoFailure::Stall));
                            enrol.extend(empty_reply());
                            enrol.extend(empty_reply());
                        } else {
                            enrol.extend(reply(wrapped_reply_status(
                                &key,
                                cmd::UPDATE_ENROLMENT,
                                attr::SESSION,
                                status::OK,
                                &twenty_byte_tlv(&ENROLMENT_ID),
                            )));
                            if failure_at == 4 {
                                enrol.push_back(IoReply::Failed(IoFailure::Disconnected));
                                enrol.extend(empty_reply());
                                enrol.extend(empty_reply());
                            } else {
                                push_enrol_commit(
                                    &mut enrol,
                                    &key,
                                    &commit_plaintext(COMMIT_HANDLE),
                                );
                                if failure_at == 5 {
                                    enrol.push_back(IoReply::Failed(IoFailure::Timeout));
                                    enrol.extend(empty_reply());
                                    enrol.extend(empty_reply());
                                } else {
                                    enrol.extend(reply(wrapped_reply(
                                        &key,
                                        cmd::ARM_CAPTURE,
                                        attr::CAPTURE,
                                        &sample_hash_plaintext(),
                                    )));
                                    enrol.push_back(IoReply::Data(
                                        cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
                                    ));
                                    enrol.push_back(IoReply::Failed(IoFailure::Stall));
                                    enrol.extend(empty_reply());
                                    enrol.extend(empty_reply());
                                }
                            }
                        }
                    }
                }
            }

            let (step, _, _) = drive_enrol(&mut plugin, &mut enrol);
            match step {
                Step::Finished(outcome) => {
                    assert!(
                        outcome.message.contains("enrolment failed"),
                        "failure {failure_at}: {}",
                        outcome.message
                    );
                }
                other => {
                    panic!("failure {failure_at}: expected a finished enrolment, got {other:?}")
                }
            }
            assert_eq!(plugin.take_payload(), None, "failure {failure_at}");
        }
    }

    #[test]
    fn twelve_samples_and_the_confirmation_are_thirteen_reported_stages() {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut script);

        let mut enrol = enrol_script(&key, MAX_ACCEPTED_SAMPLES);
        let (step, _, progress) = drive_enrol(&mut plugin, &mut enrol);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(
            progress.iter().filter(|report| !report.retry).count(),
            13,
            "twelve samples and the confirmation"
        );
        assert_eq!(progress.last().expect("a final report").completed, 13);
        assert!(progress.iter().all(|report| report.completed <= 13));
    }
}

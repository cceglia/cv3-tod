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
use cv3_core::identify::{Gallery, GalleryEntry, Identify, IdentifyError, IdentifyOutcome};
use cv3_core::operation::Operation;
use cv3_core::print::{PRINT_PAYLOAD_LEN, PrintPayload};
use cv3_core::session::{CloseError, CloseSession, OpenError, OpenSession, Session};
use cv3_core::verify::{MatchError, Verification, Verify, VerifyError};
use cv3_wire::{
    Exchange, FingerWait, IoFailure, IoReply, Transfer, event_from_finger, event_from_outcome,
};

use crate::secret::{EnrolIvs, Secrets, VerifyIvs};

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
    /// A verification or identification the sensor answered, but not with a match for the print or
    /// gallery asked about.
    ///
    /// Not an error: `fprintd` reports "no match" and the user may try again.
    NoMatch = 5,
    /// The finger never arrived. `libfprint` carries this as a retry, so `fprintd` says "retry"
    /// rather than "device error".
    Retry = 6,
    /// The operation was cancelled. `libfprint`'s task is already cancelled; the shim reports no
    /// verdict, sends no match and completes with the cancellation.
    Cancelled = 7,
    /// The print's stored record is not one this driver can read.
    DataInvalid = 8,
    /// The print carries no stored record at all.
    DataNotFound = 9,
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
    Verifying(Box<VerifyRun>),
    Identifying(Box<IdentifyRun>),
    Enrolling(Box<EnrolRun>),
    Closing(CloseRun),
    Finished,
}

/// One step of a whole verification: perform this transfer, or report the final outcome.
enum VerifyStep {
    Transfer(Transfer),
    Finished {
        output: Result<Verification, VerifyError>,
        /// The last transport failure, which selects the `libfprint` error.
        failure: Option<IoFailure>,
    },
}

/// Drives one [`Verify`] against the print's recorded match id over the shared transfer machinery.
///
/// The request is the vendor's `0x2F` handle form: the sensor matches the captured finger against
/// the one template handle the print recorded at enrolment, and the reply has to name that same
/// handle before [`PrintPayload::accepts`] accepts it.
struct VerifyRun {
    flow: Flow<Verify>,
    print: PrintPayload,
}

impl VerifyRun {
    fn new(session: Session, print: PrintPayload, ivs: VerifyIvs) -> Self {
        let operation = Verify::new(session, ivs.capture, ivs.matching)
            .with_template_handle(print.match_id())
            .with_command(cv3_core::proto::cmd::IDENTIFY_HANDLES);
        Self {
            flow: Flow::new(operation),
            print,
        }
    }

    /// The print this run is answering for.
    fn print(&self) -> PrintPayload {
        self.print
    }

    fn start(&mut self) -> VerifyStep {
        Self::classify(self.flow.start())
    }

    fn on_io_result(&mut self, reply: IoReply) -> VerifyStep {
        Self::classify(self.flow.on_io_result(reply))
    }

    fn classify(step: FlowStep<Result<Verification, VerifyError>>) -> VerifyStep {
        match step {
            FlowStep::Transfer(transfer) => VerifyStep::Transfer(transfer),
            FlowStep::Finished { output, failure } => VerifyStep::Finished { output, failure },
            // A verification always asks for the finger wait, which `Flow` performs; this cannot
            // happen, and reporting it beats panicking inside fprintd.
            FlowStep::Unsupported => VerifyStep::Finished {
                output: Err(VerifyError::UnexpectedEvent),
                failure: None,
            },
        }
    }
}

/// One step of a whole identification: perform this transfer, or report the final outcome.
enum IdentifyStep {
    Transfer(Transfer),
    Finished {
        output: Result<IdentifyOutcome, IdentifyError>,
        /// The last transport failure, which selects the `libfprint` error.
        failure: Option<IoFailure>,
    },
}

/// Drives one [`Identify`] against the gallery the client supplied.
///
/// The core decodes the gallery's payloads and asks the sensor about every usable handle in one
/// `0x2F`; the matched handle is mapped back to the caller's gallery position. Nothing here reads
/// the sensor's inventory, and nothing depends on whether it was decoded.
struct IdentifyRun {
    flow: Flow<Identify>,
}

impl IdentifyRun {
    fn new(session: Session, gallery: Gallery, ivs: VerifyIvs) -> Self {
        Self {
            flow: Flow::new(Identify::new(session, gallery, ivs.capture, ivs.matching)),
        }
    }

    fn start(&mut self) -> IdentifyStep {
        Self::classify(self.flow.start())
    }

    fn on_io_result(&mut self, reply: IoReply) -> IdentifyStep {
        Self::classify(self.flow.on_io_result(reply))
    }

    fn classify(step: FlowStep<Result<IdentifyOutcome, IdentifyError>>) -> IdentifyStep {
        match step {
            FlowStep::Transfer(transfer) => IdentifyStep::Transfer(transfer),
            FlowStep::Finished { output, failure } => IdentifyStep::Finished { output, failure },
            // An identification asks for the finger wait, which `Flow` performs; this cannot
            // happen, and reporting it beats panicking inside fprintd.
            FlowStep::Unsupported => IdentifyStep::Finished {
                output: Err(IdentifyError::UnexpectedEvent),
                failure: None,
            },
        }
    }
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
    /// The gallery position of the last successful identification, until the shim takes it.
    matched: Option<usize>,
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
            matched: None,
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
            Job::Verifying(mut run) => {
                let step = run.on_io_result(reply);
                self.after_verify_step(*run, step)
            }
            Job::Identifying(mut run) => {
                let step = run.on_io_result(reply);
                self.after_identify_step(*run, step)
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

    /// Starts a verification of `payload` — the print's `fpi-data` bytes — on the live session.
    ///
    /// The bytes are decoded here, in Rust: an empty payload is [`OutcomeKind::DataNotFound`] and
    /// anything that is not this driver's bound record is [`OutcomeKind::DataInvalid`], never a
    /// guess. The verification then runs against the match id the record names and accepts only
    /// what [`PrintPayload::accepts`] accepts. The session is never opened or closed here.
    pub fn verify_start(&mut self, payload: &[u8]) -> Step {
        match VerifyIvs::generate() {
            Ok(ivs) => self.verify_start_with(payload, ivs),
            Err(error) => Step::Finished(Outcome::error(
                OutcomeKind::General,
                format!("cv3: cannot start the verification: {error}"),
            )),
        }
    }

    /// Starts a verification with the given IVs. Test support for a deterministic run.
    pub fn verify_start_with(&mut self, payload: &[u8], ivs: VerifyIvs) -> Step {
        if !matches!(self.job, Job::Session(_)) {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: verification needs an open sensor session",
            ));
        }
        if payload.is_empty() {
            return Step::Finished(Outcome::error(
                OutcomeKind::DataNotFound,
                "cv3: the print carries no stored record, so there is nothing to verify against",
            ));
        }
        let print = match PrintPayload::decode(payload) {
            Ok(print) => print,
            Err(error) => {
                return Step::Finished(Outcome::error(
                    OutcomeKind::DataInvalid,
                    format!("cv3: the print's record cannot be verified: {error}"),
                ));
            }
        };
        let Job::Session(session) = std::mem::replace(&mut self.job, Job::Finished) else {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: verification needs an open sensor session",
            ));
        };
        self.matched = None;
        let mut run = VerifyRun::new(session, print, ivs);
        let step = run.start();
        self.after_verify_step(run, step)
    }

    /// Starts an identification over the gallery the client supplied, on the live session.
    ///
    /// Each entry is one print's position in the client's gallery and its `fpi-data` bytes. The
    /// core decodes the payloads: usable bound prints become the candidate handles of one `0x2F`
    /// request, and the matched handle is mapped back to that print's gallery position for
    /// [`Self::take_match`]. A gallery with no usable print is a no-match without a capture or a
    /// command, and leaves the session untouched. Nothing here reads the sensor's inventory or
    /// depends on it.
    pub fn identify_start(&mut self, entries: &[(usize, &[u8])]) -> Step {
        match VerifyIvs::generate() {
            Ok(ivs) => self.identify_start_with(entries, ivs),
            Err(error) => Step::Finished(Outcome::error(
                OutcomeKind::General,
                format!("cv3: cannot start the identification: {error}"),
            )),
        }
    }

    /// Starts an identification with the given IVs. Test support for a deterministic run.
    pub fn identify_start_with(&mut self, entries: &[(usize, &[u8])], ivs: VerifyIvs) -> Step {
        if !matches!(self.job, Job::Session(_)) {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: identification needs an open sensor session",
            ));
        }
        let gallery_entries: Vec<GalleryEntry<'_>> = entries
            .iter()
            .map(|(index, payload)| GalleryEntry::new(*index, payload))
            .collect();
        let gallery = Gallery::from_entries(&gallery_entries);
        let Job::Session(session) = std::mem::replace(&mut self.job, Job::Finished) else {
            return Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: identification needs an open sensor session",
            ));
        };
        self.matched = None;
        let mut run = IdentifyRun::new(session, gallery, ivs);
        let step = run.start();
        self.after_identify_step(run, step)
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
        self.matched = None;
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

    /// The gallery position of a completed identification's match, once.
    ///
    /// `None` means the last identification found no match (or has not run). The shim uses the
    /// position to report the exact `FpPrint` the client supplied, which libfprint requires.
    pub fn take_match(&mut self) -> Option<usize> {
        self.matched.take()
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
            Job::Verifying(_) => {
                self.job = Job::Finished;
                Step::Finished(Outcome {
                    kind: OutcomeKind::Ok,
                    message: "cv3: close requested during a verification".to_owned(),
                })
            }
            Job::Identifying(_) => {
                self.job = Job::Finished;
                Step::Finished(Outcome {
                    kind: OutcomeKind::Ok,
                    message: "cv3: close requested during an identification".to_owned(),
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

    fn after_verify_step(&mut self, run: VerifyRun, step: VerifyStep) -> Step {
        let print = run.print();
        match step {
            VerifyStep::Transfer(transfer) => {
                self.job = Job::Verifying(Box::new(run));
                Step::transfer(transfer)
            }
            VerifyStep::Finished {
                output,
                failure: io_failure,
            } => match output {
                Ok(Verification { verdict, session }) => {
                    // The session stays open and usable for the next operation: a no-match is a
                    // result, not a failure, and verify never closes the session itself.
                    self.job = Job::Session(session);
                    if print.accepts(&verdict) {
                        Step::Finished(Outcome::ok())
                    } else {
                        Step::Finished(Outcome::error(
                            OutcomeKind::NoMatch,
                            format!(
                                "cv3: no match for this print: verdict {}, matched handle {}, \
                                 expected {:#010x}",
                                verdict.word,
                                match verdict.matched_handle {
                                    Some(handle) => format!("{handle:#010x}"),
                                    None => "absent".to_owned(),
                                },
                                print.match_id(),
                            ),
                        ))
                    }
                }
                Err(error) => {
                    // The capture or the match tore the session down before reporting, so
                    // nothing is left to hand back.
                    self.job = Job::Finished;
                    Step::Finished(outcome_from_verify(&error, io_failure))
                }
            },
        }
    }

    fn after_identify_step(&mut self, run: IdentifyRun, step: IdentifyStep) -> Step {
        match step {
            IdentifyStep::Transfer(transfer) => {
                self.job = Job::Identifying(Box::new(run));
                Step::transfer(transfer)
            }
            IdentifyStep::Finished {
                output,
                failure: io_failure,
            } => match output {
                Ok(IdentifyOutcome::Matched { index, session, .. }) => {
                    // The session stays open for the next operation; the shim reports the print at
                    // this gallery position, which is the exact object libfprint handed us.
                    self.job = Job::Session(session);
                    self.matched = Some(index);
                    Step::Finished(Outcome::ok())
                }
                Ok(IdentifyOutcome::NoMatch { verdict, session }) => {
                    self.job = Job::Session(session);
                    self.matched = None;
                    Step::Finished(Outcome::error(
                        OutcomeKind::NoMatch,
                        format!(
                            "cv3: no print in the gallery matched: verdict {}, matched handle {}",
                            verdict.word,
                            match verdict.matched_handle {
                                Some(handle) => format!("{handle:#010x}"),
                                None => "absent".to_owned(),
                            },
                        ),
                    ))
                }
                Ok(IdentifyOutcome::EmptyGallery { session }) => {
                    self.job = Job::Session(session);
                    self.matched = None;
                    Step::Finished(Outcome::error(
                        OutcomeKind::NoMatch,
                        "cv3: no print in the gallery carries a usable bound record, so nothing \
                         was captured",
                    ))
                }
                Err(error) => {
                    // The capture or match tore the session down before reporting.
                    self.job = Job::Finished;
                    Step::Finished(outcome_from_identify(&error, io_failure))
                }
            },
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
        // A cancelled enrolment or confirmation is its own outcome. The shim completes with an
        // error and no print either way, but fprintd's cancellation result is clearer than a
        // generic failure, and the message still says the template may remain.
        BindError::Enrol(EnrolError::Cancelled { .. })
        | BindError::Confirmation(
            VerifyError::Capture(CaptureError::Cancelled)
            | VerifyError::Match(MatchError::Cancelled),
        ) => OutcomeKind::Cancelled,
        BindError::Enrol(
            EnrolError::Build(_)
            | EnrolError::Capture(_)
            | EnrolError::AttemptLimit { .. }
            | EnrolError::UnexpectedEvent { .. }
            | EnrolError::AlreadyFinished,
        )
        | BindError::Confirmation(
            VerifyError::Capture(
                CaptureError::Build(_)
                | CaptureError::FingerTimeout
                | CaptureError::UnexpectedEvent
                | CaptureError::AlreadyFinished,
            )
            | VerifyError::Match(
                MatchError::Build(_) | MatchError::UnexpectedEvent | MatchError::AlreadyFinished,
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

/// What `libfprint` is told when a verification did not accept a match.
///
/// Three outcomes are kept apart because `fprintd` reports them differently: a no-match (the
/// sensor answered a verdict that is not this print's), a retry (the finger never arrived) and a
/// device error (the transport or the protocol failed). The `Accepts` refusal and the payload
/// checks are decided before this point; only the sensor's answer is classified here.
fn outcome_from_verify(error: &VerifyError, io: Option<IoFailure>) -> Outcome {
    outcome_from_match_like(error, io, "verification")
}

/// What `libfprint` is told when an identification did not produce a matched gallery print.
///
/// The no-match outcomes are decided before this point (they are successful sensor answers); a
/// failure here is always a device or protocol error, classified like verification's.
fn outcome_from_identify(error: &IdentifyError, io: Option<IoFailure>) -> Outcome {
    match error {
        IdentifyError::Verify(error) => outcome_from_match_like(error, io, "identification"),
        IdentifyError::UnexpectedEvent | IdentifyError::AlreadyFinished => Outcome::error(
            OutcomeKind::General,
            format!("cv3: identification failed: {error}"),
        ),
    }
}

fn outcome_from_match_like(error: &VerifyError, io: Option<IoFailure>, subject: &str) -> Outcome {
    match error {
        // The user did not get a finger down in time: nothing about the sensor is wrong, so this
        // is the retry vocabulary rather than a device error.
        VerifyError::Capture(CaptureError::FingerTimeout) => Outcome::error(
            OutcomeKind::Retry,
            "cv3: no finger arrived within the finger timeout; place the finger again",
        ),
        // The action's cancellable was cancelled. The primitive's teardown has already sent the
        // sessionless `0x68` and the plain `0x04`, so the session is gone and no capture is armed.
        // This is not a verdict: the shim completes with an error and libfprint's cancelled task
        // returns G_IO_ERROR_CANCELLED to the client.
        VerifyError::Capture(CaptureError::Cancelled)
        | VerifyError::Match(MatchError::Cancelled) => Outcome::error(
            OutcomeKind::Cancelled,
            format!("cv3: the {subject} was cancelled"),
        ),
        VerifyError::Capture(CaptureError::Transport(error))
        | VerifyError::Match(MatchError::Transport(error)) => {
            let fallback = match error {
                TransportError::Disconnected => OutcomeKind::Removed,
                _ => OutcomeKind::General,
            };
            let kind = io_kind(io, fallback);
            Outcome::error(kind, format!("cv3: {subject} failed: {error}"))
        }
        // The sensor answered or refused in a way this driver does not accept: a protocol
        // failure, not a general one.
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
        ) => Outcome::error(
            OutcomeKind::Proto,
            format!("cv3: {subject} failed: {error}"),
        ),
        VerifyError::Capture(
            CaptureError::Build(_) | CaptureError::UnexpectedEvent | CaptureError::AlreadyFinished,
        )
        | VerifyError::Match(
            MatchError::Build(_) | MatchError::UnexpectedEvent | MatchError::AlreadyFinished,
        )
        | VerifyError::UnexpectedEvent
        | VerifyError::AlreadyFinished => Outcome::error(
            OutcomeKind::General,
            format!("cv3: {subject} failed: {error}"),
        ),
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
    fn a_cancelled_finger_wait_finishes_after_the_teardown_without_a_payload() {
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
        // Nothing may finish before the capture's teardown replies arrive: the sessionless cancel
        // and the close.
        enrol.extend(empty_reply());
        enrol.extend(empty_reply());

        let (step, transfers, _) = drive_enrol(&mut plugin, &mut enrol);
        match step {
            Step::Finished(outcome) => {
                assert_eq!(
                    outcome.kind,
                    OutcomeKind::Cancelled,
                    "a cancellation is its own outcome, not a generic failure: {}",
                    outcome.message
                );
                assert!(outcome.message.contains("cancelled"), "{}", outcome.message);
                assert!(
                    outcome.message.contains("cannot identify or remove it yet"),
                    "{}",
                    outcome.message
                );
            }
            other => panic!("expected a finished enrolment, got {other:?}"),
        }
        assert_eq!(
            plugin.take_payload(),
            None,
            "a cancelled enrolment stores nothing"
        );
        assert!(
            matches!(plugin.job, Job::Finished),
            "the teardown closed the session, so the state machine is finished"
        );
        assert_eq!(
            transfers
                .iter()
                .filter_map(command_of_opt)
                .collect::<Vec<_>>(),
            [
                cmd::DISCARD_ENROLMENT,
                cmd::START_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the cancel and close are sent, in that order, before the finish"
        );
        assert!(
            transfers
                .iter()
                .filter(|transfer| !matches!(transfer, Transfer::FingerIn { .. }))
                .all(|transfer| !transfer.cancellable()),
            "only the finger wait was cancellable"
        );

        // The failed enrolment already closed the session; closing again sends nothing and a fresh
        // operation must start with a new open.
        let (step, close_transfers) = close_run(&mut plugin, &mut VecDeque::new());
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert!(close_transfers.is_empty());
        assert_eq!(
            plugin.enrol_start_with(enroled_ivs()),
            Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: enrolment needs an open sensor session"
            )),
            "a cancelled enrolment leaves no session to continue on"
        );
    }

    #[test]
    fn a_cancelled_confirmation_finishes_as_cancelled_and_stores_nothing() {
        let key = session_key();
        let mut open: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut plugin = opened_plugin(&mut open);

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
        push_enrol_commit(&mut enrol, &key, &commit_plaintext(COMMIT_HANDLE));
        // The confirmation's arm succeeds, then the client cancels the touch.
        enrol.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        enrol.push_back(IoReply::Failed(IoFailure::Cancelled));
        enrol.extend(empty_reply());
        enrol.extend(empty_reply());

        let (step, transfers, _) = drive_enrol(&mut plugin, &mut enrol);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Cancelled);
                assert!(
                    outcome.message.contains("confirmation"),
                    "the message names the cancelled touch: {}",
                    outcome.message
                );
                assert!(
                    outcome.message.contains("may remain"),
                    "the template caveat is kept: {}",
                    outcome.message
                );
            }
            other => panic!("expected a finished enrolment, got {other:?}"),
        }
        assert_eq!(plugin.take_payload(), None, "nothing is stored");
        assert!(matches!(plugin.job, Job::Finished));
        assert_eq!(
            transfers
                .iter()
                .filter_map(command_of_opt)
                .collect::<Vec<_>>()
                .last(),
            Some(&cmd::CLOSE_SESSION),
            "the confirmation's teardown closed the session"
        );
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

    // ---- Verification through the session -----------------------------------------------------

    use cv3_core::print::{PRINT_PAYLOAD_LEN as BOUND_RECORD_LEN, PrintPayload, PrintSource};

    /// The bytes ticket 13 stores on an enrolled print: a bound record naming `COMMIT_HANDLE`.
    fn bound_payload(handle: u32) -> Vec<u8> {
        PrintPayload::bound(ENROLMENT_ID, PrintSource::EnrolmentId, handle)
            .encode()
            .to_vec()
    }

    /// An open session and the key its frames use.
    fn opened_for_verification() -> (Plugin, [u8; SESSION_KEY_LEN]) {
        let key = session_key();
        let mut script: VecDeque<IoReply> = [
            reply(challenge_reply(0)),
            reply(response_reply(0)),
            reply(open_reply(0)),
        ]
        .into_iter()
        .flatten()
        .collect();
        (opened_plugin(&mut script), key)
    }

    fn verify_ivs() -> VerifyIvs {
        VerifyIvs {
            capture: [0x80; 16],
            matching: [0x90; 16],
        }
    }

    /// Starts a verification of `payload` and drives it against scripted transport results.
    fn drive_verify(
        plugin: &mut Plugin,
        payload: &[u8],
        script: &mut VecDeque<IoReply>,
    ) -> (Step, Vec<Transfer>) {
        let first = plugin.verify_start_with(payload, verify_ivs());
        drive(plugin, first, script)
    }

    /// The two commands one verification sends: the capture arm, then the handle-form match.
    fn verify_commands(transfers: &[Transfer]) -> Vec<u16> {
        transfers.iter().filter_map(command_of_opt).collect()
    }

    #[test]
    fn a_verification_of_the_bound_print_reports_a_match_and_keeps_the_session() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 1, COMMIT_HANDLE);

        let (step, transfers) =
            drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(
            verify_commands(&transfers),
            [cmd::ARM_CAPTURE, cmd::IDENTIFY_HANDLES],
            "a capture arm, then 0x2F against the recorded handle"
        );
        assert_eq!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .count(),
            1
        );
        assert!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .all(Transfer::cancellable),
            "the finger wait is the cancellable transfer"
        );
        assert!(
            transfers
                .iter()
                .filter(|transfer| !matches!(transfer, Transfer::FingerIn { .. }))
                .all(|transfer| !transfer.cancellable()),
            "no command transfer is ever cancellable"
        );
        assert!(
            matches!(plugin.job, Job::Session(_)),
            "the session is usable for the next operation"
        );

        // And it really is: the close still writes the plain 0x04 on it.
        let mut close = empty_reply().into_iter().collect();
        let (step, transfers) = close_run(&mut plugin, &mut close);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(command_of(&transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn a_no_match_is_reported_without_an_error_and_keeps_the_session() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 0, 0);

        let (step, _) = drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::NoMatch);
                assert!(outcome.message.contains("no match"), "{}", outcome.message);
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert!(matches!(plugin.job, Job::Session(_)));
    }

    #[test]
    fn a_match_for_another_handle_is_a_no_match_for_this_print() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        // Verdict 1, but the sensor matched the other enrolled template.
        push_confirmation(&mut script, &key, 1, 0x002f_1a08);

        let (step, _) = drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::NoMatch);
                assert!(
                    outcome.message.contains("0x002f1a08"),
                    "the message names the handle the sensor matched: {}",
                    outcome.message
                );
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert!(matches!(plugin.job, Job::Session(_)));
    }

    #[test]
    fn a_reply_that_does_not_decrypt_is_a_protocol_failure_not_a_match() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        // A body too short to be a wrapped reply: the match reply itself is malformed.
        script.push_back(IoReply::Completed);
        script.push_back(announcement(8));
        script.push_back(IoReply::Data(vec![0u8; 8]));
        // The match's own teardown: the sessionless cancel and the close.
        script.extend(empty_reply());
        script.extend(empty_reply());

        let (step, transfers) =
            drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Proto);
                assert!(outcome.message.contains("malformed"), "{}", outcome.message);
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert_eq!(
            verify_commands(&transfers)
                .iter()
                .filter(|command| **command == cmd::CLOSE_SESSION)
                .count(),
            1,
            "the match's teardown closed the handle it could not trust"
        );
        assert!(
            matches!(plugin.job, Job::Finished),
            "the teardown closed the session, so there is none to hand back"
        );
    }

    #[test]
    fn a_print_without_a_record_is_data_not_found_before_any_transfer() {
        let (mut plugin, _) = opened_for_verification();

        let (step, transfers) = drive_verify(&mut plugin, &[], &mut VecDeque::new());

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::DataNotFound);
                assert!(
                    outcome.message.contains("no stored record"),
                    "{}",
                    outcome.message
                );
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert!(transfers.is_empty(), "nothing was sent: {transfers:?}");
        assert!(
            matches!(plugin.job, Job::Session(_)),
            "an unusable payload never touched the session"
        );
    }

    #[test]
    fn a_record_of_another_version_or_length_is_data_invalid() {
        let mut unknown_version = bound_payload(COMMIT_HANDLE);
        unknown_version[4] = 2;
        let short = bound_payload(COMMIT_HANDLE)[..BOUND_RECORD_LEN - 1].to_vec();
        let mut foreign = bound_payload(COMMIT_HANDLE);
        foreign[0] = b'X';

        for (payload, why) in [
            (unknown_version, "an unknown version"),
            (short, "a short record"),
            (foreign, "a foreign magic"),
        ] {
            let (mut plugin, _) = opened_for_verification();
            let (step, transfers) = drive_verify(&mut plugin, &payload, &mut VecDeque::new());

            match step {
                Step::Finished(outcome) => {
                    assert_eq!(outcome.kind, OutcomeKind::DataInvalid, "{why}");
                }
                other => panic!("{why}: expected a finished verification, got {other:?}"),
            }
            assert!(transfers.is_empty(), "{why}: nothing was sent");
            assert!(
                matches!(plugin.job, Job::Session(_)),
                "{why}: the session is untouched"
            );
        }
    }

    #[test]
    fn a_finger_that_never_arrives_is_a_retry_not_a_device_error() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Failed(IoFailure::Timeout));
        // The capture's teardown after the finger timeout.
        script.extend(empty_reply());
        script.extend(empty_reply());

        let (step, _) = drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(
                    outcome.kind,
                    OutcomeKind::Retry,
                    "fprintd must offer a retry, not a device error: {}",
                    outcome.message
                );
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert!(matches!(plugin.job, Job::Finished));
    }

    #[test]
    fn a_transport_failure_at_each_verification_stage_is_reported() {
        // The failure is injected at the arm's write, its announcement, its body and the finger
        // read, in that order.
        for failure_at in 0..4 {
            let (mut plugin, key) = opened_for_verification();
            let mut script = VecDeque::new();
            match failure_at {
                0 => script.push_back(IoReply::Failed(IoFailure::Disconnected)),
                1 => {
                    script.push_back(IoReply::Completed);
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                2 => {
                    script.push_back(IoReply::Completed);
                    script.push_back(announcement(56));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                _ => {
                    script.extend(reply(wrapped_reply(
                        &key,
                        cmd::ARM_CAPTURE,
                        attr::CAPTURE,
                        &sample_hash_plaintext(),
                    )));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
            }
            script.extend(empty_reply());
            script.extend(empty_reply());

            let (step, transfers) =
                drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

            match step {
                Step::Finished(outcome) => {
                    let expected = if failure_at == 0 {
                        OutcomeKind::Removed
                    } else {
                        OutcomeKind::General
                    };
                    assert_eq!(outcome.kind, expected, "failure {failure_at}");
                    assert!(
                        outcome.message.contains("verification failed"),
                        "failure {failure_at}: {}",
                        outcome.message
                    );
                }
                other => {
                    panic!("failure {failure_at}: expected a finished verification, got {other:?}")
                }
            }
            assert!(
                matches!(plugin.job, Job::Finished),
                "failure {failure_at}: the teardown closed the session"
            );
            assert_eq!(
                verify_commands(&transfers).last(),
                Some(&cmd::CLOSE_SESSION),
                "failure {failure_at}: the best-effort teardown ran"
            );
        }
    }

    #[test]
    fn a_timestamp_request_during_the_verify_finger_wait_is_answered() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        // The sensor asks for the clock before delivering the finger event.
        script.push_back(IoReply::Data(
            cv3_wire::timestamp::HOST_TIMESTAMP_INTERRUPT
                .to_le_bytes()
                .to_vec(),
        ));
        script.push_back(IoReply::Completed);
        script.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        let match_plaintext = {
            let mut plaintext = vec![0u8; 56];
            plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
            plaintext[8..12].copy_from_slice(&1u32.to_le_bytes());
            plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
            plaintext[20..24].copy_from_slice(&COMMIT_HANDLE.to_le_bytes());
            plaintext
        };
        script.extend(reply(wrapped_reply(
            &key,
            cmd::IDENTIFY_HANDLES,
            attr::CAPTURE,
            &match_plaintext,
        )));

        let (step, transfers) =
            drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

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
        assert!(matches!(plugin.job, Job::Session(_)));
    }

    #[test]
    fn a_cancelled_finger_wait_finishes_after_the_teardown_without_a_match_or_a_store() {
        let (mut plugin, key) = opened_for_verification();
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Failed(IoFailure::Cancelled));
        // The capture's teardown: the sessionless cancel and the close. The finish cannot arrive
        // until both replies have been consumed.
        script.extend(empty_reply());
        script.extend(empty_reply());

        let (step, transfers) =
            drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Cancelled);
                assert!(
                    !matches!(outcome.kind, OutcomeKind::NoMatch | OutcomeKind::Retry),
                    "a cancellation is not a verdict and not a retry"
                );
                assert!(outcome.message.contains("cancelled"), "{}", outcome.message);
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        // A cancelled verify never reaches the match request: one arm, then the teardown.
        assert_eq!(
            verify_commands(&transfers),
            [cmd::ARM_CAPTURE, cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION],
            "the teardown is complete before the finish, and no 0x2F was sent"
        );
        assert_eq!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .count(),
            1,
            "the cancelled wait is not retried behind the client's back"
        );
        assert!(
            matches!(plugin.job, Job::Finished),
            "the teardown closed the session, so the state machine is finished"
        );
        assert_eq!(
            plugin.take_payload(),
            None,
            "a cancelled verify stores nothing"
        );

        // Closing again is harmless and sends nothing: the core already closed the handle.
        let (step, close_transfers) = close_run(&mut plugin, &mut VecDeque::new());
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert!(close_transfers.is_empty());

        // The next operation must be a fresh open, not a second verify on the dead session.
        assert_eq!(
            plugin.verify_start_with(&bound_payload(COMMIT_HANDLE), verify_ivs()),
            Step::Finished(Outcome::error(
                OutcomeKind::General,
                "cv3: verification needs an open sensor session"
            ))
        );
    }

    #[test]
    fn a_cancel_never_aborts_a_command_transfer_and_the_wait_is_the_only_cancellable() {
        let (mut plugin, key) = opened_for_verification();
        let first = plugin.verify_start_with(&bound_payload(COMMIT_HANDLE), verify_ivs());
        let mut transfers = Vec::new();

        // The arm is a command transfer and is not cancellable. The verification has not finished:
        // it is waiting for that command's result.
        let Step::Transfer(arm) = first else {
            panic!("expected the capture arm, got {first:?}");
        };
        assert!(matches!(arm, Transfer::Out { .. }), "the arm is a command");
        assert!(!arm.cancellable());
        assert!(
            matches!(plugin.job, Job::Verifying(_)),
            "the action is still in progress while its command is in flight"
        );
        transfers.push(arm);

        // Feed the arm's three results explicitly. Only after them does the cancellable finger
        // wait appear.
        let mut arm_replies = reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        ))
        .into_iter();
        let Step::Transfer(announcement) =
            plugin.on_transfer(arm_replies.next().expect("the arm completed"))
        else {
            panic!("expected the arm's announcement read");
        };
        assert!(matches!(announcement, Transfer::InterruptIn { .. }));
        transfers.push(announcement);
        let Step::Transfer(body) =
            plugin.on_transfer(arm_replies.next().expect("the arm was announced"))
        else {
            panic!("expected the arm's reply body read");
        };
        assert!(matches!(body, Transfer::BulkIn { .. }));
        transfers.push(body);
        let step = plugin.on_transfer(arm_replies.next().expect("the arm reply body"));

        let Step::Transfer(finger) = step else {
            panic!("expected the finger wait, got {step:?}");
        };
        assert!(matches!(finger, Transfer::FingerIn { .. }));
        assert!(finger.cancellable());
        transfers.push(finger);

        // A cancellation ends that wait; the teardown commands are ordinary, non-cancellable
        // transfers and are awaited like the arm was.
        let mut step = plugin.on_transfer(IoReply::Failed(IoFailure::Cancelled));
        let mut teardown = VecDeque::new();
        teardown.extend(empty_reply());
        teardown.extend(empty_reply());
        while let Step::Transfer(transfer) = step {
            assert!(
                !transfer.cancellable(),
                "a teardown command must never be submitted cancellable"
            );
            transfers.push(transfer);
            step = plugin.on_transfer(
                teardown
                    .pop_front()
                    .expect("the teardown script has both replies"),
            );
        }

        assert!(
            matches!(step, Step::Finished(ref outcome) if outcome.kind == OutcomeKind::Cancelled)
        );
        assert_eq!(
            verify_commands(&transfers),
            [cmd::ARM_CAPTURE, cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION]
        );
        assert!(
            transfers
                .iter()
                .filter(|transfer| !matches!(transfer, Transfer::FingerIn { .. }))
                .all(|transfer| !transfer.cancellable()),
            "every command transfer is submitted without a cancellable"
        );
        assert!(matches!(plugin.job, Job::Finished));
    }

    #[test]
    fn ten_cancelled_verifications_then_fresh_opens_leave_the_state_machine_clean() {
        let key = session_key();
        let mut plugin = Plugin::new();

        for cycle in 0..10 {
            let mut open: VecDeque<IoReply> = [
                reply(challenge_reply(0)),
                reply(response_reply(0)),
                reply(open_reply(0)),
            ]
            .into_iter()
            .flatten()
            .collect();
            let (step, open_transfers) = open_run(&mut plugin, &mut open);
            assert_eq!(step, Step::Finished(Outcome::ok()), "cycle {cycle}: open");
            assert_eq!(
                open_transfers
                    .iter()
                    .filter_map(command_of_opt)
                    .collect::<Vec<_>>(),
                [cmd::CHALLENGE, cmd::CHALLENGE_RESPONSE, cmd::OPEN_SESSION],
                "cycle {cycle}: a fresh open is the handshake and the wrapped 0x02 only"
            );
            assert!(
                matches!(plugin.job, Job::Session(_)),
                "cycle {cycle}: the open leaves a live session"
            );

            let mut script = VecDeque::new();
            script.extend(reply(wrapped_reply(
                &key,
                cmd::ARM_CAPTURE,
                attr::CAPTURE,
                &sample_hash_plaintext(),
            )));
            script.push_back(IoReply::Failed(IoFailure::Cancelled));
            script.extend(empty_reply());
            script.extend(empty_reply());

            let (step, transfers) =
                drive_verify(&mut plugin, &bound_payload(COMMIT_HANDLE), &mut script);
            assert!(
                matches!(step, Step::Finished(ref outcome) if outcome.kind == OutcomeKind::Cancelled),
                "cycle {cycle}: the cancellation finishes promptly"
            );
            assert_eq!(
                verify_commands(&transfers),
                [cmd::ARM_CAPTURE, cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION],
                "cycle {cycle}: no capture is left armed and no handle is left open"
            );
            assert!(
                matches!(plugin.job, Job::Finished),
                "cycle {cycle}: the state machine is finished, not stale"
            );
            assert_eq!(plugin.take_payload(), None, "cycle {cycle}: nothing stored");

            let (step, close_transfers) = close_run(&mut plugin, &mut VecDeque::new());
            assert_eq!(step, Step::Finished(Outcome::ok()), "cycle {cycle}: close");
            assert!(
                close_transfers.is_empty(),
                "cycle {cycle}: the cancel already closed the handle"
            );
        }
    }

    #[test]
    fn a_verification_needs_an_open_session() {
        let mut plugin = Plugin::new();
        let (step, transfers) = drive_verify(
            &mut plugin,
            &bound_payload(COMMIT_HANDLE),
            &mut VecDeque::new(),
        );

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::General);
                assert!(outcome.message.contains("session"), "{}", outcome.message);
            }
            other => panic!("expected a finished verification, got {other:?}"),
        }
        assert!(transfers.is_empty());
    }

    // ---- Identification through the session ---------------------------------------------------

    const FIRST_GALLERY_HANDLE: u32 = 0x0070_69a9;
    const SECOND_GALLERY_HANDLE: u32 = 0x002f_1a08;

    /// Starts an identification over `payloads` and drives it against scripted transport results.
    fn drive_identify(
        plugin: &mut Plugin,
        payloads: &[&[u8]],
        script: &mut VecDeque<IoReply>,
    ) -> (Step, Vec<Transfer>) {
        let entries: Vec<(usize, &[u8])> = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| (index, *payload))
            .collect();
        let first = plugin.identify_start_with(&entries, verify_ivs());
        drive(plugin, first, script)
    }

    /// The decrypted TLV of one command frame, read with the session key the test already has.
    fn request_tlv_of(key: &[u8; SESSION_KEY_LEN], frame: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&frame[24..40]);
        let plaintext =
            cv3_core::crypto::decrypt_cbc(key, &iv, &frame[44..]).expect("the request decrypts");
        let tlv_len = u32::from_le_bytes(frame[40..44].try_into().expect("four bytes")) as usize;
        plaintext[..tlv_len].to_vec()
    }

    /// The last `0x2F` frame the run wrote, decrypted to its parameter list.
    fn identify_request(key: &[u8; SESSION_KEY_LEN], transfers: &[Transfer]) -> Vec<u8> {
        let frame = transfers
            .iter()
            .rfind(|transfer| command_of_opt(transfer) == Some(cmd::IDENTIFY_HANDLES))
            .and_then(|transfer| match transfer {
                Transfer::Out { frame, .. } => Some(frame.as_slice()),
                _ => None,
            })
            .expect("the identification wrote a 0x2F");
        request_tlv_of(key, frame)
    }

    #[test]
    fn identification_matches_the_gallery_print_whose_handle_the_sensor_names() {
        let (mut plugin, key) = opened_for_verification();
        let first = bound_payload(FIRST_GALLERY_HANDLE);
        let second = bound_payload(SECOND_GALLERY_HANDLE);
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 1, SECOND_GALLERY_HANDLE);

        let (step, transfers) = drive_identify(&mut plugin, &[&first, &second], &mut script);

        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(
            plugin.take_match(),
            Some(1),
            "the second gallery print, not merely some print"
        );
        assert_eq!(plugin.take_match(), None, "the position is handed out once");
        assert_eq!(
            verify_commands(&transfers),
            [cmd::ARM_CAPTURE, cmd::IDENTIFY_HANDLES],
            "one capture, one match request for the whole gallery"
        );
        assert_eq!(
            identify_request(&key, &transfers),
            cv3_core::verify::request_tlv(
                HANDLE,
                &[FIRST_GALLERY_HANDLE, SECOND_GALLERY_HANDLE],
                None
            ),
            "the type-2 array carries every candidate handle"
        );
        let match_frame = transfers
            .iter()
            .rfind(|transfer| command_of_opt(transfer) == Some(cmd::IDENTIFY_HANDLES))
            .and_then(|transfer| match transfer {
                Transfer::Out { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("a match frame");
        assert_eq!(
            match_frame[10],
            attr::CAPTURE,
            "attr 0x47 is the match request, not the inventory query's 0x42"
        );
        assert!(
            matches!(plugin.job, Job::Session(_)),
            "a match leaves the session usable"
        );

        let mut close = empty_reply().into_iter().collect();
        let (step, close_transfers) = close_run(&mut plugin, &mut close);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(command_of(&close_transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn a_handle_outside_the_gallery_is_a_no_match_that_keeps_the_session() {
        let (mut plugin, key) = opened_for_verification();
        let gallery = bound_payload(FIRST_GALLERY_HANDLE);
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 1, 0x0bad_f00d);

        let (step, _) = drive_identify(&mut plugin, &[&gallery], &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::NoMatch);
                assert!(outcome.message.contains("no print"), "{}", outcome.message);
                assert!(
                    outcome.message.contains("0x0badf00d"),
                    "the message names the handle the sensor matched: {}",
                    outcome.message
                );
            }
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert_eq!(plugin.take_match(), None);
        assert!(matches!(plugin.job, Job::Session(_)));

        let mut close = empty_reply().into_iter().collect();
        let (step, close_transfers) = close_run(&mut plugin, &mut close);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(command_of(&close_transfers[0]), cmd::CLOSE_SESSION);
    }

    #[test]
    fn an_empty_gallery_is_a_no_match_without_a_capture() {
        let (mut plugin, _) = opened_for_verification();

        let (step, transfers) = drive_identify(&mut plugin, &[], &mut VecDeque::new());

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::NoMatch);
                assert!(outcome.message.contains("no print"), "{}", outcome.message);
            }
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert!(transfers.is_empty(), "nothing was captured: {transfers:?}");
        assert_eq!(plugin.take_match(), None);
        assert!(
            matches!(plugin.job, Job::Session(_)),
            "an unusable gallery never touched the session"
        );
    }

    #[test]
    fn a_gallery_of_unusable_records_is_a_no_match_without_a_capture() {
        let (mut plugin, _) = opened_for_verification();
        let mut foreign = bound_payload(FIRST_GALLERY_HANDLE);
        foreign[0] = b'X';
        let mut unbound = bound_payload(SECOND_GALLERY_HANDLE);
        unbound[5] &= !0x01;
        let short = bound_payload(SECOND_GALLERY_HANDLE)[..BOUND_RECORD_LEN - 1].to_vec();

        let (step, transfers) = drive_identify(
            &mut plugin,
            &[&[], &foreign, &unbound, &short],
            &mut VecDeque::new(),
        );

        match step {
            Step::Finished(outcome) => assert_eq!(outcome.kind, OutcomeKind::NoMatch),
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert!(transfers.is_empty(), "nothing was sent: {transfers:?}");
        assert_eq!(plugin.take_match(), None);
        assert!(matches!(plugin.job, Job::Session(_)));
    }

    #[test]
    fn a_duplicated_handle_is_never_a_match_for_either_print() {
        let (mut plugin, key) = opened_for_verification();
        let first = bound_payload(FIRST_GALLERY_HANDLE);
        let second = bound_payload(SECOND_GALLERY_HANDLE);

        // Both copies name the same template: the gallery is ambiguous and nothing is captured.
        let (step, transfers) =
            drive_identify(&mut plugin, &[&first, &first], &mut VecDeque::new());
        match step {
            Step::Finished(outcome) => assert_eq!(outcome.kind, OutcomeKind::NoMatch),
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert!(transfers.is_empty(), "the ambiguous handle was not sent");
        assert_eq!(plugin.take_match(), None);

        // A unique print next to the duplicated pair is still a candidate, but the duplicated
        // handle the sensor names is not.
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 1, FIRST_GALLERY_HANDLE);
        let (step, _) = drive_identify(&mut plugin, &[&first, &first, &second], &mut script);
        match step {
            Step::Finished(outcome) => assert_eq!(outcome.kind, OutcomeKind::NoMatch),
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert_eq!(plugin.take_match(), None);
        assert!(matches!(plugin.job, Job::Session(_)));

        // The unique print still matches at its own gallery position.
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 1, SECOND_GALLERY_HANDLE);
        let (step, _) = drive_identify(&mut plugin, &[&first, &first, &second], &mut script);
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert_eq!(plugin.take_match(), Some(2));
    }

    #[test]
    fn a_zero_verdict_is_a_no_match_that_keeps_the_session() {
        let (mut plugin, key) = opened_for_verification();
        let gallery = bound_payload(FIRST_GALLERY_HANDLE);
        let mut script = VecDeque::new();
        push_confirmation(&mut script, &key, 0, 0);

        let (step, _) = drive_identify(&mut plugin, &[&gallery], &mut script);

        match step {
            Step::Finished(outcome) => assert_eq!(outcome.kind, OutcomeKind::NoMatch),
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert_eq!(plugin.take_match(), None);
        assert!(matches!(plugin.job, Job::Session(_)));
    }

    #[test]
    fn a_malformed_identification_reply_is_a_protocol_error_not_a_no_match() {
        let (mut plugin, key) = opened_for_verification();
        let gallery = bound_payload(FIRST_GALLERY_HANDLE);
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Data(
            cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
        ));
        script.push_back(IoReply::Completed);
        script.push_back(announcement(8));
        script.push_back(IoReply::Data(vec![0u8; 8]));
        script.extend(empty_reply());
        script.extend(empty_reply());

        let (step, transfers) = drive_identify(&mut plugin, &[&gallery], &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Proto);
                assert!(
                    outcome.message.contains("identification failed"),
                    "{}",
                    outcome.message
                );
                assert!(outcome.message.contains("malformed"), "{}", outcome.message);
            }
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert_eq!(plugin.take_match(), None);
        assert!(
            matches!(plugin.job, Job::Finished),
            "the match's teardown closed the session"
        );
        assert_eq!(
            verify_commands(&transfers).last(),
            Some(&cmd::CLOSE_SESSION)
        );
    }

    #[test]
    fn a_transport_failure_at_each_identification_stage_is_reported() {
        // The failure is injected at the arm's write, its announcement, its body, the finger read,
        // the match's write, its announcement and its body, in that order.
        for failure_at in 0..7 {
            let (mut plugin, key) = opened_for_verification();
            let gallery = bound_payload(FIRST_GALLERY_HANDLE);
            let mut script = VecDeque::new();
            match failure_at {
                0 => script.push_back(IoReply::Failed(IoFailure::Disconnected)),
                1 => {
                    script.push_back(IoReply::Completed);
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                2 => {
                    script.push_back(IoReply::Completed);
                    script.push_back(announcement(56));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                3 => {
                    script.extend(reply(wrapped_reply(
                        &key,
                        cmd::ARM_CAPTURE,
                        attr::CAPTURE,
                        &sample_hash_plaintext(),
                    )));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                4 => {
                    script.extend(reply(wrapped_reply(
                        &key,
                        cmd::ARM_CAPTURE,
                        attr::CAPTURE,
                        &sample_hash_plaintext(),
                    )));
                    script.push_back(IoReply::Data(
                        cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
                    ));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                5 => {
                    script.extend(reply(wrapped_reply(
                        &key,
                        cmd::ARM_CAPTURE,
                        attr::CAPTURE,
                        &sample_hash_plaintext(),
                    )));
                    script.push_back(IoReply::Data(
                        cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
                    ));
                    script.push_back(IoReply::Completed);
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
                _ => {
                    script.extend(reply(wrapped_reply(
                        &key,
                        cmd::ARM_CAPTURE,
                        attr::CAPTURE,
                        &sample_hash_plaintext(),
                    )));
                    script.push_back(IoReply::Data(
                        cv3_core::proto::interrupt::FINGER.to_le_bytes().to_vec(),
                    ));
                    script.push_back(IoReply::Completed);
                    script.push_back(announcement(56));
                    script.push_back(IoReply::Failed(IoFailure::Stall));
                }
            }
            script.extend(empty_reply());
            script.extend(empty_reply());

            let (step, transfers) = drive_identify(&mut plugin, &[&gallery], &mut script);

            match step {
                Step::Finished(outcome) => {
                    let expected = if failure_at == 0 {
                        OutcomeKind::Removed
                    } else {
                        OutcomeKind::General
                    };
                    assert_eq!(outcome.kind, expected, "failure {failure_at}");
                    assert!(
                        outcome.message.contains("identification failed"),
                        "failure {failure_at}: {}",
                        outcome.message
                    );
                }
                other => panic!(
                    "failure {failure_at}: expected a finished identification, got {other:?}"
                ),
            }
            assert_eq!(plugin.take_match(), None, "failure {failure_at}");
            assert!(
                matches!(plugin.job, Job::Finished),
                "failure {failure_at}: the teardown closed the session"
            );
            assert_eq!(
                verify_commands(&transfers).last(),
                Some(&cmd::CLOSE_SESSION),
                "failure {failure_at}: the best-effort teardown ran"
            );
        }
    }

    #[test]
    fn a_cancelled_identification_tears_down_without_a_match() {
        let (mut plugin, key) = opened_for_verification();
        let gallery = bound_payload(FIRST_GALLERY_HANDLE);
        let mut script = VecDeque::new();
        script.extend(reply(wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &sample_hash_plaintext(),
        )));
        script.push_back(IoReply::Failed(IoFailure::Cancelled));
        script.extend(empty_reply());
        script.extend(empty_reply());

        let (step, transfers) = drive_identify(&mut plugin, &[&gallery], &mut script);

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Cancelled);
                assert!(
                    !matches!(outcome.kind, OutcomeKind::NoMatch | OutcomeKind::Retry),
                    "a cancellation is not a verdict and not a retry"
                );
                assert!(outcome.message.contains("cancelled"), "{}", outcome.message);
            }
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert_eq!(
            verify_commands(&transfers),
            [cmd::ARM_CAPTURE, cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION],
            "the teardown is complete and no 0x2F was sent"
        );
        assert_eq!(
            transfers
                .iter()
                .filter(|transfer| matches!(transfer, Transfer::FingerIn { .. }))
                .count(),
            1,
            "the cancelled wait is not retried"
        );
        assert_eq!(plugin.take_match(), None);
        assert!(matches!(plugin.job, Job::Finished));

        let (step, close_transfers) = close_run(&mut plugin, &mut VecDeque::new());
        assert_eq!(step, Step::Finished(Outcome::ok()));
        assert!(close_transfers.is_empty(), "the cancel already closed it");
    }

    #[test]
    fn an_identification_needs_an_open_session() {
        let mut plugin = Plugin::new();
        let gallery = bound_payload(FIRST_GALLERY_HANDLE);
        let (step, transfers) = drive_identify(&mut plugin, &[&gallery], &mut VecDeque::new());

        match step {
            Step::Finished(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::General);
                assert!(outcome.message.contains("session"), "{}", outcome.message);
            }
            other => panic!("expected a finished identification, got {other:?}"),
        }
        assert!(transfers.is_empty());
    }
}

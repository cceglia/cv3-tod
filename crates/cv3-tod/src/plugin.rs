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

use cv3_core::event::{Action, TransportError};
use cv3_core::handshake::{Handshake, HandshakeError};
use cv3_core::operation::Operation;
use cv3_core::session::{CloseError, CloseSession, OpenError, OpenSession, Session};
use cv3_wire::{Exchange, IoFailure, IoReply, Transfer, event_from_outcome};

use crate::secret::Secrets;

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
struct Flow<O: Operation> {
    operation: O,
    exchange: Option<Exchange>,
    failure: Option<IoFailure>,
}

impl<O: Operation> Flow<O> {
    fn new(operation: O) -> Self {
        Self {
            operation,
            exchange: None,
            failure: None,
        }
    }

    fn start(&mut self) -> FlowStep<O::Output> {
        let action = self.operation.start();
        self.advance(action)
    }

    fn on_io_result(&mut self, reply: IoReply) -> FlowStep<O::Output> {
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
                self.exchange = Some(Exchange::new(frame));
                self.next()
            }
            Action::WaitFinger => FlowStep::Unsupported,
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
    Closing(CloseRun),
    Finished,
}

/// The whole plugin-side session state for one device.
///
/// One instance lives per `FpDevice` instance, owned by the shim. It starts idle; after a successful
/// open it holds the session; a failed open leaves it finished, and the shim destroys it and creates
/// a fresh one for the next claim.
pub struct Plugin {
    job: Job,
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin {
    pub fn new() -> Self {
        Self { job: Job::Idle }
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
    let kind = match failure {
        Some(IoFailure::Disconnected) => OutcomeKind::Removed,
        Some(IoFailure::Busy) => OutcomeKind::Busy,
        Some(_) => OutcomeKind::General,
        None => match error {
            TransportError::Disconnected => OutcomeKind::Removed,
            _ => OutcomeKind::General,
        },
    };
    Outcome::error(kind, format!("cv3: opening the sensor failed: {error}"))
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
}

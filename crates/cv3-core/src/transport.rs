//! The transport contract: everything the core asks of whatever carries its bytes.
//!
//! The core never chooses a USB transfer. One command is one frame out and one outcome back:
//! exactly one of a reply (status and body), an empty reply, a transport error or cancellation.
//! The finger wait is the only other action, and it answers with the finger event, a transport
//! error or cancellation. USB endpoints, timeouts, threads and callbacks live in an
//! implementation, never here.
//!
//! Four implementations exist. The probe's USB transport and the C shim's libfprint transport
//! live in their own crates; [`ScriptedTransport`], [`FailingTransport`] and the replay transport
//! in [`crate::transcript`] are test support. All of them satisfy the same trait, so the contract
//! tests run once and are run against every implementation.
//!
//! [`run`] is the whole driver loop. It is the same loop the probe and the shim use; an operation
//! that needs a new state never needs a new loop.

use std::collections::VecDeque;

use crate::event::{Action, Event, TransportError};
use crate::operation::Operation;

/// Sends frames and waits for the finger event on behalf of a core operation.
pub trait Transport {
    /// Sends one command frame and returns its outcome.
    ///
    /// Only [`Event::Reply`], [`Event::ReplyWithoutBody`], [`Event::Transport`] and
    /// [`Event::Cancelled`] are valid answers. The transport performs the protocol's
    /// out/interrupt/in exchange and reads an announced body before returning, so the next command
    /// can never start with reply bytes still in flight. A command transfer is never cancelled.
    fn command(&mut self, frame: &[u8]) -> Event;

    /// Waits for the finger event.
    ///
    /// Only [`Event::Finger`], [`Event::Transport`] and [`Event::Cancelled`] are valid answers. A
    /// real transport makes this wait cancellable; that is the only transfer the protocol allows
    /// to be abandoned.
    fn wait_finger(&mut self) -> Event;
}

/// Drives one operation to completion over one transport.
///
/// This is deliberately the whole loop: `start`, then one event per action, until the operation
/// finishes. The transport owns time, so the core needs no timer, thread or callback.
pub fn run<O, T>(operation: &mut O, transport: &mut T) -> O::Output
where
    O: Operation,
    T: Transport + ?Sized,
{
    let mut action = operation.start();
    loop {
        match action {
            Action::Send(frame) => action = operation.step(transport.command(&frame)),
            Action::WaitFinger => action = operation.step(transport.wait_finger()),
            Action::Finish(result) => return result,
        }
    }
}

/// One scripted answer, in the core's own event vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedOutcome {
    /// A reply with the command status from the frame header and its body.
    Reply { status: u32, body: Vec<u8> },
    /// The command completed without an announced body.
    ReplyWithoutBody,
    /// The sensor reported that a finger was read.
    Finger,
    /// A transport failure.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
}

impl From<Event> for ScriptedOutcome {
    fn from(event: Event) -> Self {
        match event {
            Event::Reply { status, body } => Self::Reply { status, body },
            Event::ReplyWithoutBody => Self::ReplyWithoutBody,
            Event::Finger => Self::Finger,
            Event::Transport(error) => Self::Transport(error),
            Event::Cancelled => Self::Cancelled,
        }
    }
}

impl ScriptedOutcome {
    /// Turns the scripted answer into the event an operation consumes.
    pub fn into_event(self) -> Event {
        match self {
            Self::Reply { status, body } => Event::Reply { status, body },
            Self::ReplyWithoutBody => Event::ReplyWithoutBody,
            Self::Finger => Event::Finger,
            Self::Transport(error) => Event::Transport(error),
            Self::Cancelled => Event::Cancelled,
        }
    }
}

/// A sensor scripted from a queue of outcomes, recording every command frame it was sent.
///
/// This is test support, not a production transport. An operation that asks for more commands
/// than the queue holds receives a transport error that says so, rather than hanging or panicking.
#[derive(Debug, Default, Clone)]
pub struct ScriptedTransport {
    outcomes: VecDeque<ScriptedOutcome>,
    sent: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    /// Builds a scripted sensor from the outcomes it should produce, in order.
    pub fn new(outcomes: impl IntoIterator<Item = ScriptedOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    /// Appends one more outcome, for a scenario that decides its next reply after seeing a frame.
    pub fn push(&mut self, outcome: impl Into<ScriptedOutcome>) {
        self.outcomes.push_back(outcome.into());
    }

    /// Every command frame the operation asked to send, in order.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// How many scripted outcomes have not been consumed.
    pub fn remaining(&self) -> usize {
        self.outcomes.len()
    }

    /// Asserts the exact frames the operation sent.
    ///
    /// Test support: a mismatch panics with both sequences so the failing test says what the
    /// operation wanted to send.
    pub fn assert_sent(&self, expected: &[Vec<u8>]) {
        assert_eq!(
            self.sent, expected,
            "the operation sent a different frame sequence"
        );
    }

    /// Asserts that the scenario consumed every scripted outcome.
    pub fn assert_exhausted(&self) {
        assert_eq!(
            self.remaining(),
            0,
            "the operation finished with scripted outcomes left"
        );
    }

    fn next(&mut self) -> Event {
        match self.outcomes.pop_front() {
            Some(outcome) => outcome.into_event(),
            None => Event::Transport(TransportError::Other(
                "the scripted transport ran out of outcomes".to_owned(),
            )),
        }
    }
}

impl Transport for ScriptedTransport {
    fn command(&mut self, frame: &[u8]) -> Event {
        self.sent.push(frame.to_vec());
        self.next()
    }

    fn wait_finger(&mut self) -> Event {
        self.next()
    }
}

/// A transport that answers every call with one fixed event.
///
/// This is the failure-injecting implementation the transport contract is run against: a reply,
/// a transport error or a cancellation can be made to happen at any point without scripting a
/// whole exchange. It is test support, not a production transport.
#[derive(Debug, Clone)]
pub struct FailingTransport {
    event: Event,
    sent: Vec<Vec<u8>>,
}

impl FailingTransport {
    /// Builds a transport whose every command and finger wait yields `event`.
    pub fn new(event: Event) -> Self {
        Self {
            event,
            sent: Vec::new(),
        }
    }

    /// Every command frame the operation asked to send, in order.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }
}

impl Transport for FailingTransport {
    fn command(&mut self, frame: &[u8]) -> Event {
        self.sent.push(frame.to_vec());
        self.event.clone()
    }

    fn wait_finger(&mut self) -> Event {
        self.event.clone()
    }
}

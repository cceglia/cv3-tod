//! The transport contract, run once and against every implementation.
//!
//! A transport answers a command with a reply, an empty reply, a transport error or cancellation,
//! and a finger wait with a finger, an error or cancellation. These tests do not care which
//! implementation supplies the answers.

use cv3_core::frame;
use cv3_core::proto::{attr, cmd};
use cv3_core::transcript::{ReplayTransport, Transcript, TranscriptRecord};
use cv3_core::transport::{FailingTransport, ScriptedOutcome, ScriptedTransport, Transport};
use cv3_core::{Event, TransportError};

fn host_frame() -> Vec<u8> {
    frame::build_plain(cmd::VERIFY, attr::CAPTURE, 7, &[0u8; 4])
}

fn record(event: &Event) -> TranscriptRecord {
    match event {
        Event::Reply { status, body } => TranscriptRecord::Reply {
            status: *status,
            body: body.clone(),
        },
        Event::ReplyWithoutBody => TranscriptRecord::ReplyWithoutBody,
        Event::Finger => TranscriptRecord::Finger,
        Event::Transport(error) => TranscriptRecord::Transport(error.clone()),
        Event::Cancelled => TranscriptRecord::Cancelled,
    }
}

fn command_cases() -> Vec<Event> {
    vec![
        Event::Reply {
            status: 0,
            body: vec![1, 2, 3],
        },
        Event::ReplyWithoutBody,
        Event::Transport(TransportError::Other("boom".to_owned())),
        Event::Transport(TransportError::Timeout),
        Event::Cancelled,
    ]
}

fn finger_cases() -> Vec<Event> {
    vec![
        Event::Finger,
        Event::Transport(TransportError::Timeout),
        Event::Cancelled,
    ]
}

fn run_command_contract(factory: impl Fn(Event) -> Box<dyn Transport>) {
    for expected in command_cases() {
        let mut transport = factory(expected.clone());
        assert_eq!(
            transport.command(&host_frame()),
            expected,
            "a command must answer with the scripted outcome"
        );
    }
}

fn run_finger_contract(factory: impl Fn(Event) -> Box<dyn Transport>) {
    for expected in finger_cases() {
        let mut transport = factory(expected.clone());
        assert_eq!(
            transport.wait_finger(),
            expected,
            "a finger wait must answer with the scripted outcome"
        );
    }
}

#[test]
fn the_scripted_transport_obeys_the_command_contract() {
    run_command_contract(|event| Box::new(ScriptedTransport::new([ScriptedOutcome::from(event)])));
}

#[test]
fn the_scripted_transport_obeys_the_finger_contract() {
    run_finger_contract(|event| Box::new(ScriptedTransport::new([ScriptedOutcome::from(event)])));
}

#[test]
fn the_failure_injecting_transport_obeys_the_command_contract() {
    run_command_contract(|event| Box::new(FailingTransport::new(event)));
}

#[test]
fn the_failure_injecting_transport_obeys_the_finger_contract() {
    run_finger_contract(|event| Box::new(FailingTransport::new(event)));
}

#[test]
fn the_replay_transport_obeys_the_command_contract() {
    run_command_contract(|event| {
        let mut transcript = Transcript::new("contract");
        transcript.push(TranscriptRecord::HostFrame(host_frame()));
        transcript.push(record(&event));
        Box::new(ReplayTransport::new(transcript))
    });
}

#[test]
fn the_replay_transport_obeys_the_finger_contract() {
    run_finger_contract(|event| {
        let mut transcript = Transcript::new("contract");
        transcript.push(record(&event));
        Box::new(ReplayTransport::new(transcript))
    });
}

//! Transcript serialisation, recording, replay and divergence.

mod common;

use common::{
    HANDLE, challenge_reply, client_nonce, fixed_iv, host_key, host_nonce, open_reply,
    response_reply,
};
use cv3_core::crypto::HostKey;
use cv3_core::frame;
use cv3_core::proto::{attr, cmd};
use cv3_core::session::{OpenError, OpenSession};
use cv3_core::transcript::{
    Divergence, RecordingTransport, ReplayTransport, Transcript, TranscriptError, TranscriptRecord,
};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, Transport, run};
use cv3_core::{Event, Handshake, TransportError};

fn host_frame() -> Vec<u8> {
    frame::build_plain(cmd::MATCH, attr::CAPTURE, HANDLE, &[0u8; 4])
}

fn all_records() -> Vec<TranscriptRecord> {
    vec![
        TranscriptRecord::HostFrame(host_frame()),
        TranscriptRecord::Reply {
            status: 0x85,
            body: vec![1, 2, 3, 4],
        },
        TranscriptRecord::ReplyWithoutBody,
        TranscriptRecord::Finger,
        TranscriptRecord::Transport(TransportError::Timeout),
        TranscriptRecord::Transport(TransportError::Disconnected),
        TranscriptRecord::Transport(TransportError::Stall),
        TranscriptRecord::Transport(TransportError::Other("usbfs said no".to_owned())),
        TranscriptRecord::Cancelled,
    ]
}

#[test]
fn a_transcript_round_trips_every_record_kind() {
    let mut transcript = Transcript::new("handshake");
    for record in all_records() {
        transcript.push(record);
    }

    let bytes = transcript.to_bytes();
    let parsed = Transcript::from_bytes(&bytes).expect("a transcript this build wrote parses");

    assert_eq!(parsed, transcript);
    assert_eq!(parsed.command(), "handshake");
    assert_eq!(parsed.records().len(), 9);
}

#[test]
fn a_transcript_is_wire_only_version_one() {
    let mut transcript = Transcript::new("handshake");
    transcript.push(TranscriptRecord::ReplyWithoutBody);
    let bytes = transcript.to_bytes();

    assert_eq!(
        u16::from_le_bytes([bytes[8], bytes[9]]),
        1,
        "v1 is the wire-only format; v2 carried session material and is gone"
    );
    assert_eq!(
        Transcript::from_bytes(&bytes).expect("a transcript this build wrote parses"),
        transcript
    );
}

#[test]
fn an_unknown_version_is_rejected() {
    let transcript = Transcript::new("handshake");
    let mut bytes = transcript.to_bytes();
    bytes[8..10].copy_from_slice(&99u16.to_le_bytes());

    assert_eq!(
        Transcript::from_bytes(&bytes),
        Err(TranscriptError::UnknownVersion(99))
    );
}

#[test]
fn replay_matches_on_command_attribute_and_handle_not_payload() {
    let recorded = frame::build_plain(cmd::MATCH, attr::CAPTURE, HANDLE, &[0u8; 4]);
    let mut changed = recorded.clone();
    changed[44] ^= 0xff;

    let mut transcript = Transcript::new("match");
    transcript.push(TranscriptRecord::HostFrame(recorded));
    transcript.push(TranscriptRecord::ReplyWithoutBody);

    let mut replay = ReplayTransport::new(transcript);
    assert_eq!(replay.command(&changed), Event::ReplyWithoutBody);
    assert_eq!(replay.finish(), Ok(()));
}

#[test]
fn a_truncated_transcript_is_rejected_at_every_prefix_without_panicking() {
    let mut transcript = Transcript::new("open");
    for record in all_records() {
        transcript.push(record);
    }
    let bytes = transcript.to_bytes();

    for length in 0..bytes.len() {
        assert!(
            Transcript::from_bytes(&bytes[..length]).is_err(),
            "a {length}-byte prefix must not parse"
        );
    }
    assert!(Transcript::from_bytes(&bytes).is_ok());
}

#[test]
fn a_corrupt_length_is_rejected() {
    let mut transcript = Transcript::new("handshake");
    transcript.push(TranscriptRecord::HostFrame(host_frame()));
    let mut bytes = transcript.to_bytes();
    let offset = 8 + 2 + 4 + transcript.command().len() + 4 + 1;
    bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(matches!(
        Transcript::from_bytes(&bytes),
        Err(TranscriptError::BadLength {
            field: "host frame length",
            ..
        })
    ));
}

#[test]
fn a_bad_magic_and_an_unknown_record_tag_are_rejected() {
    let mut transcript = Transcript::new("handshake");
    transcript.push(TranscriptRecord::ReplyWithoutBody);
    let mut bytes = transcript.to_bytes();
    bytes[0] = 0;
    assert!(matches!(
        Transcript::from_bytes(&bytes),
        Err(TranscriptError::BadMagic(_))
    ));

    let mut bytes = transcript.to_bytes();
    let tag = 8 + 2 + 4 + transcript.command().len() + 4;
    bytes[tag] = 99;
    assert_eq!(
        Transcript::from_bytes(&bytes),
        Err(TranscriptError::UnknownRecord(99))
    );
}

#[test]
fn trailing_bytes_after_the_last_record_are_rejected() {
    let mut transcript = Transcript::new("handshake");
    transcript.push(TranscriptRecord::Finger);
    let mut bytes = transcript.to_bytes();
    bytes.push(0);

    assert_eq!(
        Transcript::from_bytes(&bytes),
        Err(TranscriptError::TrailingBytes { count: 1 })
    );
}

#[test]
fn a_recording_captures_both_directions_in_order() {
    let inner = ScriptedTransport::new([
        ScriptedOutcome::Reply {
            status: 3,
            body: vec![9, 8],
        },
        ScriptedOutcome::Finger,
    ]);
    let mut recording = RecordingTransport::new(inner, "match");

    assert_eq!(
        recording.command(&host_frame()),
        Event::Reply {
            status: 3,
            body: vec![9, 8],
        }
    );
    assert_eq!(recording.wait_finger(), Event::Finger);

    let transcript = recording.into_transcript();
    assert_eq!(transcript.command(), "match");
    assert_eq!(
        transcript.records(),
        &[
            TranscriptRecord::HostFrame(host_frame()),
            TranscriptRecord::Reply {
                status: 3,
                body: vec![9, 8],
            },
            TranscriptRecord::Finger,
        ]
    );
}

#[test]
fn replay_feeds_the_recorded_device_outcomes() {
    let mut transcript = Transcript::new("match");
    transcript.push(TranscriptRecord::HostFrame(host_frame()));
    transcript.push(TranscriptRecord::Reply {
        status: 0x85,
        body: vec![7],
    });

    let mut replay = ReplayTransport::new(transcript);
    assert_eq!(
        replay.command(&host_frame()),
        Event::Reply {
            status: 0x85,
            body: vec![7],
        }
    );
    assert_eq!(replay.sent(), &[host_frame()]);
    assert_eq!(replay.finish(), Ok(()));
    assert!(replay.divergence().is_none());
}

#[test]
fn a_divergent_command_is_a_distinct_outcome() {
    let mut transcript = Transcript::new("match");
    transcript.push(TranscriptRecord::HostFrame(host_frame()));
    transcript.push(TranscriptRecord::ReplyWithoutBody);

    let mut replay = ReplayTransport::new(transcript);
    let different = frame::build_plain(cmd::OPEN_SESSION, attr::SESSION, HANDLE, &[]);
    let event = replay.command(&different);

    assert!(
        matches!(event, Event::Transport(TransportError::Other(_))),
        "a divergence reaches the operation as a transport failure"
    );
    assert!(matches!(
        replay.divergence(),
        Some(Divergence::CommandMismatch { .. })
    ));
    assert!(replay.finish().is_err());
}

#[test]
fn leftover_records_are_a_divergence_not_a_success() {
    let mut transcript = Transcript::new("match");
    transcript.push(TranscriptRecord::HostFrame(host_frame()));
    transcript.push(TranscriptRecord::ReplyWithoutBody);
    transcript.push(TranscriptRecord::Finger);

    let mut replay = ReplayTransport::new(transcript);
    assert_eq!(replay.command(&host_frame()), Event::ReplyWithoutBody);
    assert_eq!(
        replay.finish(),
        Err(Divergence::UnconsumedRecords { count: 1 })
    );
    assert_eq!(
        replay.divergence(),
        Some(&Divergence::UnconsumedRecords { count: 1 })
    );
}

#[test]
fn recording_then_replaying_a_handshake_reproduces_the_outcome() {
    let mut recording = RecordingTransport::new(
        ScriptedTransport::new([
            ScriptedOutcome::Reply {
                status: 0,
                body: challenge_reply(0),
            },
            ScriptedOutcome::Reply {
                status: 0,
                body: response_reply(0),
            },
            ScriptedOutcome::ReplyWithoutBody,
        ]),
        "handshake",
    );
    let mut recorded_operation = Handshake::new(client_nonce(), host_key(), host_nonce());
    let recorded = run(&mut recorded_operation, &mut recording).expect("the recording succeeds");
    let transcript = recording.into_transcript();

    // A different host keypair is what a fresh run has, and what replay must tolerate.
    let mut replay = ReplayTransport::new(transcript);
    let mut fresh_operation = Handshake::new(
        client_nonce(),
        HostKey::from_bytes(&[1u8; 32]).expect("valid scalar"),
        host_nonce(),
    );
    let replayed = run(&mut fresh_operation, &mut replay).expect("the replay succeeds");

    assert_eq!(replayed.handle, recorded.handle);
    assert_eq!(replayed.client_nonce_len, recorded.client_nonce_len);
    assert_eq!(replayed.device_nonce_len, recorded.device_nonce_len);
    assert_eq!(replayed.host_nonce_len, recorded.host_nonce_len);
    assert_eq!(replayed.next_sequence(), recorded.next_sequence());
    assert_ne!(
        replayed.key().as_bytes(),
        recorded.key().as_bytes(),
        "a fresh host key derives a different session key"
    );
    assert_eq!(replay.finish(), Ok(()));
}

#[test]
fn recording_then_replaying_a_failed_open_reproduces_the_error() {
    let mut recording = RecordingTransport::new(
        ScriptedTransport::new([
            ScriptedOutcome::Reply {
                status: 0,
                body: challenge_reply(0),
            },
            ScriptedOutcome::Reply {
                status: 0,
                body: response_reply(0),
            },
            ScriptedOutcome::Reply {
                status: 0x0c,
                body: open_reply(0x0c),
            },
            ScriptedOutcome::ReplyWithoutBody,
        ]),
        "open",
    );
    let mut recorded_handshake =
        Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let recorded_session =
        run(&mut recorded_handshake, &mut recording).expect("the recorded handshake succeeds");
    let mut recorded_open = OpenSession::new(recorded_session, fixed_iv());
    assert_eq!(
        run(&mut recorded_open, &mut recording),
        Err(OpenError::SensorStatus(0x0c))
    );
    let transcript = recording.into_transcript();

    let mut replay = ReplayTransport::new(transcript);
    let mut fresh_handshake = Handshake::new(
        client_nonce(),
        HostKey::from_bytes(&[1u8; 32]).expect("valid scalar"),
        host_nonce(),
    )
    .keeping_handle();
    let fresh_session = run(&mut fresh_handshake, &mut replay).expect("the replayed handshake");
    let mut fresh_open = OpenSession::new(fresh_session, [0x99; 16]);
    assert_eq!(
        run(&mut fresh_open, &mut replay),
        Err(OpenError::SensorStatus(0x0c))
    );
    assert_eq!(replay.finish(), Ok(()));
}

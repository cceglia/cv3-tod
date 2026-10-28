//! End-to-end core scenarios driven through the scripted transport.
//!
//! These tests assert the exact frames an operation asks to send and the outcome it reports. They
//! cover the operations that exist: the handshake, open, close and capture. The remaining biometric
//! scenarios in the SPEC's testing decisions belong to the tickets that build those operations.

mod common;

use common::{
    HANDLE, SAMPLE_HASH, arm_frame, capture_reply, challenge_frame, challenge_reply, client_nonce,
    fixed_iv, host_key, host_nonce, open_reply, opened_session, response_frame, response_reply,
    sample_hash_plaintext,
};
use cv3_core::capture::{Capture, CaptureError};
use cv3_core::frame::{self, FrameError};
use cv3_core::proto::{attr, cmd};
use cv3_core::session::{
    CloseSession, OPEN_PLAINTEXT_LEN, OPEN_TLV, OpenError, OpenSession, Teardown, UnwrapError,
};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::{Event, Handshake, HandshakeError, TransportError};

fn handshake_transport(replies: impl IntoIterator<Item = ScriptedOutcome>) -> ScriptedTransport {
    ScriptedTransport::new(replies)
}

#[test]
fn a_handshake_over_the_scripted_transport_sends_the_documented_frames() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
        ScriptedOutcome::ReplyWithoutBody,
    ]);
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    let session = run(&mut operation, &mut transport).expect("the scripted sensor accepts");

    assert_eq!(session.handle, HANDLE);
    assert_eq!(session.client_nonce_len, 20);
    assert_eq!(session.device_nonce_len, 20);
    assert_eq!(session.host_nonce_len, 20);
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn a_rejected_challenge_over_the_scripted_transport_ends_without_a_close() {
    let mut transport = handshake_transport([ScriptedOutcome::Reply {
        status: 0x0c,
        body: challenge_reply(0x0c),
    }]);
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(HandshakeError::RejectedChallenge(0x0c))
    );
    transport.assert_sent(&[challenge_frame()]);
    transport.assert_exhausted();
}

#[test]
fn a_transport_error_before_the_handle_is_learned_finishes_at_once() {
    let mut transport = handshake_transport([ScriptedOutcome::Transport(TransportError::Timeout)]);
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(HandshakeError::Transport(TransportError::Timeout))
    );
    transport.assert_sent(&[challenge_frame()]);
    transport.assert_exhausted();
}

#[test]
fn a_cancellation_after_the_handle_is_learned_releases_it() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Cancelled,
        ScriptedOutcome::ReplyWithoutBody,
    ]);
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(HandshakeError::Cancelled)
    );
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn an_open_and_close_over_the_scripted_transport_send_the_exact_frames() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
    ]);
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, &mut transport).expect("the handshake keeps the handle");
    assert_eq!(
        transport.sent().len(),
        2,
        "a kept handle is not released by the handshake"
    );

    let iv = fixed_iv();
    let expected_open = session
        .wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            OPEN_PLAINTEXT_LEN,
            &iv,
            0,
        )
        .expect("the open constants build a frame");
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: open_reply(0),
    });
    let mut open = OpenSession::new(session, iv);
    let opened = run(&mut open, &mut transport).expect("the scripted sensor opens the session");
    assert_eq!(opened.handle, HANDLE);
    assert_eq!(opened.next_sequence(), 1, "0x02 consumed sequence zero");

    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let mut close = CloseSession::new(opened.handle);
    run(&mut close, &mut transport).expect("the close is best effort");

    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        expected_open,
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn a_rejected_open_releases_the_handle_over_the_scripted_transport() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
    ]);
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, &mut transport).expect("the handshake keeps the handle");
    let iv = fixed_iv();
    let expected_open = session
        .wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            OPEN_PLAINTEXT_LEN,
            &iv,
            0,
        )
        .expect("the open constants build a frame");

    transport.push(ScriptedOutcome::Reply {
        status: 0x0c,
        body: open_reply(0x0c),
    });
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let mut open = OpenSession::new(session, iv);

    assert_eq!(
        run(&mut open, &mut transport),
        Err(OpenError::SensorStatus(0x0c))
    );
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        expected_open,
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn a_transport_error_during_open_releases_the_handle() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
    ]);
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, &mut transport).expect("the handshake keeps the handle");
    let iv = fixed_iv();
    let expected_open = session
        .wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            OPEN_PLAINTEXT_LEN,
            &iv,
            0,
        )
        .expect("the open constants build a frame");

    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let mut open = OpenSession::new(session, iv);

    assert_eq!(
        run(&mut open, &mut transport),
        Err(OpenError::Transport(TransportError::Timeout))
    );
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        expected_open,
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_open_releases_the_handle() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
    ]);
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, &mut transport).expect("the handshake keeps the handle");
    let iv = fixed_iv();
    let expected_open = session
        .wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            OPEN_PLAINTEXT_LEN,
            &iv,
            0,
        )
        .expect("the open constants build a frame");

    transport.push(ScriptedOutcome::Cancelled);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let mut open = OpenSession::new(session, iv);

    assert_eq!(run(&mut open, &mut transport), Err(OpenError::Cancelled));
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        expected_open,
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn a_close_transport_error_is_reported_but_the_handle_is_locally_closed() {
    let mut transport = handshake_transport([
        ScriptedOutcome::Reply {
            status: 0,
            body: challenge_reply(0),
        },
        ScriptedOutcome::Reply {
            status: 0,
            body: response_reply(0),
        },
    ]);
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, &mut transport).expect("the handshake keeps the handle");

    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    let mut close = CloseSession::new(session.handle);
    drop(session);

    assert_eq!(
        run(&mut close, &mut transport),
        Err(cv3_core::CloseError::Transport(
            TransportError::Disconnected
        ))
    );
    transport.assert_sent(&[
        challenge_frame(),
        response_frame(),
        frame::build_close_handle(HANDLE),
    ]);
    transport.assert_exhausted();
}

#[test]
fn an_unscripted_command_is_a_transport_error_rather_than_a_hang() {
    let mut transport = ScriptedTransport::default();
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    assert!(matches!(
        run(&mut operation, &mut transport),
        Err(HandshakeError::Transport(TransportError::Other(_)))
    ));
    transport.assert_sent(&[challenge_frame()]);
}

#[test]
fn a_finger_event_is_never_confused_with_a_command_reply() {
    // The scripted transport hands the operation exactly what it queued; an operation that never
    // asks for a finger sees it as an unexpected event and tears down.
    let mut transport = ScriptedTransport::new([Event::Finger.into()]);
    let mut operation = Handshake::new(client_nonce(), host_key(), host_nonce());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(HandshakeError::UnexpectedEvent)
    );
    transport.assert_sent(&[challenge_frame()]);
}

/// The two replies a failed capture's best-effort teardown consumes.
fn teardown_replies() -> [ScriptedOutcome; 2] {
    [
        ScriptedOutcome::ReplyWithoutBody,
        ScriptedOutcome::ReplyWithoutBody,
    ]
}

#[test]
fn a_capture_arms_at_the_next_sequence_waits_and_returns_the_sample_hash() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    assert_eq!(transport.sent().len(), 3, "handshake and open only");
    let expected_arm = arm_frame(&session, &fixed_iv());

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Finger);
    let mut capture = Capture::new(session, fixed_iv());

    let captured = run(&mut capture, &mut transport).expect("the finger was read");
    assert_eq!(captured.sample_hash, SAMPLE_HASH);
    assert_eq!(captured.session.handle, HANDLE);
    assert_eq!(
        captured.session.next_sequence(),
        2,
        "0x02 consumed zero and the 0x66 reply consumed one"
    );

    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let handle = captured.session.handle;
    drop(captured.session);
    let mut teardown = Teardown::new(handle);
    assert_eq!(run(&mut teardown, &mut transport), Ok(()));

    let sent = transport.sent();
    assert_eq!(sent.len(), 6);
    assert_eq!(sent[3], expected_arm, "0x66 at the session's next sequence");
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_capture_pending_reply_is_its_own_outcome_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let expected_arm = arm_frame(&session, &fixed_iv());

    transport.push(ScriptedOutcome::Reply {
        status: 0x85,
        body: capture_reply(&session, 0x85, &[0u8; 28]),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::AlreadyPending)
    );

    let sent = transport.sent();
    assert_eq!(sent.len(), 6);
    assert_eq!(sent[3], expected_arm);
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_zero_status_reply_without_a_sample_hash_is_its_own_outcome() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &[0u8; 28]),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::NoSampleHash)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_finger_timeout_is_distinct_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::FingerTimeout)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_transport_failure_at_the_arm_is_distinct_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::Transport(TransportError::Disconnected))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_transport_failure_reading_the_arm_reply_is_reported_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Transport(TransportError::Other(
        "reply read failed".to_owned(),
    )));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::Transport(TransportError::Other(
            "reply read failed".to_owned()
        )))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_transport_failure_at_the_finger_wait_is_not_a_finger_timeout() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::Transport(TransportError::Disconnected))
    );
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_finger_wait_is_distinct_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Cancelled);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::Cancelled)
    );
    transport.assert_exhausted();
}

#[test]
fn a_short_arm_reply_is_malformed_and_does_not_panic() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: vec![0u8; 10],
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert!(matches!(
        run(&mut capture, &mut transport),
        Err(CaptureError::MalformedReply(UnwrapError::Frame(
            FrameError::Short { .. }
        )))
    ));
    transport.assert_exhausted();
}

#[test]
fn an_oversized_arm_reply_is_malformed_and_does_not_panic() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    let oversized = frame::build_wrapped(
        cmd::ARM_CAPTURE,
        attr::CAPTURE,
        HANDLE,
        &fixed_iv(),
        0,
        &vec![0u8; 4_112],
    );
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: oversized,
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert!(matches!(
        run(&mut capture, &mut transport),
        Err(CaptureError::MalformedReply(
            UnwrapError::CiphertextTooLarge { .. }
        ))
    ));
    transport.assert_exhausted();
}

#[test]
fn a_reply_where_the_finger_was_expected_is_unexpected_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut capture = Capture::new(session, fixed_iv());

    assert_eq!(
        run(&mut capture, &mut transport),
        Err(CaptureError::UnexpectedEvent)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

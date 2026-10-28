//! Cancellation and the wrap-sequence rule, driven through the scripted transport.
//!
//! These scenarios cover the one-session run `cvctl cancel-then-verify` performs, the mid-session
//! `0x68` layout, the outcomes of [`CancelCapture`], and both readings of the wrap-sequence rule.
//! Every expected frame is built independently here from the protocol constants, at an explicit
//! sequence number where the sequence is the assertion.

mod common;

use common::{
    HANDLE, SAMPLE_HASH, arm_frame_at, capture_reply, match_frame_at, match_plaintext, match_reply,
    opened_session, sample_hash_plaintext,
};
use cv3_core::cancel::{CancelCapture, CancelError};
use cv3_core::capture::{ArmCapture, ArmOutcome, CaptureError};
use cv3_core::crypto;
use cv3_core::frame::{self, HEADER_LEN, PARAM_LEN_OFFSET};
use cv3_core::proto::{attr, cmd, status};
use cv3_core::session::{SequenceRule, Session, Teardown};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::verify::{Verify, VerifyError};
use cv3_core::{TransportError, Verdict, Verification};

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
}

fn iv(seed: u8) -> [u8; crypto::BLOCK_LEN] {
    let mut iv = [0u8; crypto::BLOCK_LEN];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    iv
}

fn teardown_replies() -> [ScriptedOutcome; 2] {
    [
        ScriptedOutcome::ReplyWithoutBody,
        ScriptedOutcome::ReplyWithoutBody,
    ]
}

fn push_arm(transport: &mut ScriptedTransport, session: &Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(session, 0, &sample_hash_plaintext()),
    });
}

fn push_match(transport: &mut ScriptedTransport, session: &Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(session, 0, &match_plaintext(1, Some(&common::MATCH_VALUE))),
    });
}

#[test]
fn one_session_arms_cancels_and_then_verifies_with_the_documented_frames_and_sequences() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    assert_eq!(session.next_sequence(), 1, "0x02 consumed sequence zero");

    let first_arm_iv = iv(0x60);
    let second_arm_iv = iv(0x70);
    let match_iv = iv(0x80);
    let expected_first_arm = arm_frame_at(&session, &first_arm_iv, 1);

    // Arm only: the reply is consumed, the finger is not awaited.
    push_arm(&mut transport, &session);
    let mut arm = ArmCapture::new(session, first_arm_iv);
    let armed = match run(&mut arm, &mut transport).expect("the sensor armed the capture") {
        ArmOutcome::Armed(armed) => armed,
        other => panic!("expected an armed capture, got {other:?}"),
    };
    assert_eq!(armed.sample_hash, SAMPLE_HASH);
    assert_eq!(armed.session.next_sequence(), 2, "the 0x66 reply advanced");
    assert_eq!(
        transport.sent().len(),
        4,
        "handshake, open and the arm; no finger wait and no teardown"
    );
    assert_eq!(transport.sent()[3], expected_first_arm);

    // Cancel the armed capture with the mid-session frame, which is plain and consumes no seq.
    let expected_cancel = frame::build_cancel_capture_mid(HANDLE);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let session = run(&mut CancelCapture::new(armed.session), &mut transport)
        .expect("the sensor accepted the mid-session cancel");
    assert_eq!(
        session.next_sequence(),
        2,
        "the plain 0x68 does not advance the sequence"
    );
    assert_eq!(transport.sent()[4], expected_cancel);

    // A whole verification in the same session.
    let expected_second_arm = arm_frame_at(&session, &second_arm_iv, 2);
    let expected_match = match_frame_at(&session, &match_iv, 3);
    push_arm(&mut transport, &session);
    transport.push(ScriptedOutcome::Finger);
    push_match(&mut transport, &session);
    let mut verify = Verify::new(session, second_arm_iv, match_iv);
    let Verification { verdict, session } =
        run(&mut verify, &mut transport).expect("the finger matched in the same session");

    assert_eq!(
        verdict,
        Verdict {
            word: 1,
            matched: true,
            value: Some(common::MATCH_VALUE),
            plaintext_len: 52,
            reply_len: HEADER_LEN + 64,
        }
    );
    assert_eq!(
        session.next_sequence(),
        4,
        "the 0x73 reply advanced once more"
    );

    // Tear the one session down: sessionless 0x68, then 0x04.
    let mut teardown = Teardown::new(session.handle);
    drop(session);
    for outcome in teardown_replies() {
        transport.push(outcome);
    }
    assert_eq!(run(&mut teardown, &mut transport), Ok(()));

    let sent = transport.sent();
    assert_eq!(
        sent.len(),
        9,
        "0x23, 0x24, 0x02, 0x66, 0x68 mid, 0x66, 0x73, 0x68, 0x04"
    );
    assert_eq!(sent[3], expected_first_arm, "first arm at sequence 1");
    assert_eq!(sent[4], expected_cancel, "mid-session cancel after it");
    assert_eq!(sent[5], expected_second_arm, "second arm at sequence 2");
    assert_eq!(sent[6], expected_match, "match at sequence 3");
    assert_eq!(sent[7], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[8], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_capture_rearms_at_the_first_arms_sequence_by_default() {
    for (rewind, expected_second_arm, label) in [
        (true, 1, "default: rewind to N"),
        (false, 2, "--retry-next: N+1"),
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        assert_eq!(session.next_sequence(), 1, "0x02 consumed sequence zero");

        let first_arm_iv = iv(0x60);
        push_arm(&mut transport, &session);
        let armed = match run(&mut ArmCapture::new(session, first_arm_iv), &mut transport)
            .expect("the first arm captures")
        {
            ArmOutcome::Armed(armed) => armed,
            other => panic!("{label}: expected an armed capture, got {other:?}"),
        };
        assert_eq!(
            armed.session.next_sequence(),
            2,
            "{label}: the first arm reply advanced"
        );

        transport.push(ScriptedOutcome::ReplyWithoutBody);
        let mut session = run(&mut CancelCapture::new(armed.session), &mut transport)
            .expect("the mid-session cancel succeeds");
        if rewind {
            session.rewind_sequence();
        }

        let second_arm_iv = iv(0x70);
        let expected = arm_frame_at(&session, &second_arm_iv, expected_second_arm);
        push_arm(&mut transport, &session);
        let rearmed = match run(&mut ArmCapture::new(session, second_arm_iv), &mut transport)
            .expect("the re-arm captures")
        {
            ArmOutcome::Armed(armed) => armed,
            other => panic!("{label}: expected an armed capture, got {other:?}"),
        };

        assert_eq!(
            transport.sent()[5],
            expected,
            "{label}: the second 0x66 carries sequence {expected_second_arm}"
        );
        assert_eq!(
            rearmed.session.next_sequence(),
            expected_second_arm + 1,
            "{label}: the re-arm reply advances from there"
        );
        transport.assert_exhausted();
    }
}

#[test]
fn the_mid_session_cancel_frame_is_plain_with_the_live_handle_and_twelve_bytes() {
    let frame = frame::build_cancel_capture_mid(HANDLE);

    assert_eq!(
        frame.len(),
        56,
        "a 44-byte header and a 12-byte parameter block"
    );
    assert_eq!(le32(&frame, 0), 1, "magic");
    assert_eq!(le32(&frame, 4), 56, "total length");
    assert_eq!(&frame[8..10], &cmd::CANCEL_CAPTURE.to_le_bytes(), "0x68");
    assert_eq!(frame[10], attr::CANCEL_SESSION, "attribute 0x40");
    assert_eq!(frame[11], 0x00, "plain encoding");
    assert_eq!(
        le32(&frame, 16),
        HANDLE,
        "header handle is the session handle"
    );
    assert_eq!(
        le32(&frame, PARAM_LEN_OFFSET),
        12,
        "declared parameter length"
    );
    assert_eq!(le32(&frame, HEADER_LEN), 0, "tag");
    assert_eq!(le32(&frame, HEADER_LEN + 4), 4, "value length");
    assert_eq!(le32(&frame, HEADER_LEN + 8), HANDLE, "handle parameter");

    // It is not the sessionless teardown cancel: that one has attr 0x44 and a zero header handle.
    let teardown = frame::build_cancel_capture(HANDLE);
    assert_eq!(teardown[10], attr::CANCEL_SESSIONLESS);
    assert_eq!(le32(&teardown, 16), 0);
}

#[test]
fn a_mid_session_cancel_accepts_a_reply_with_a_body_and_leaves_the_session_open() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: frame::build_plain_reply(
            cmd::CANCEL_CAPTURE,
            attr::CANCEL_SESSION,
            HANDLE,
            0,
            &[0u8; 8],
        ),
    });
    let returned = run(&mut CancelCapture::new(session), &mut transport)
        .expect("a body-bearing reply still means the capture is cancelled");

    assert_eq!(returned.handle, HANDLE);
    assert_eq!(
        returned.next_sequence(),
        1,
        "the plain cancel leaves the sequence alone"
    );
    assert_eq!(
        transport.sent().last(),
        Some(&frame::build_cancel_capture_mid(HANDLE)),
        "the reply body is consumed and no teardown follows"
    );
    transport.assert_exhausted();
}

#[test]
fn a_mid_session_cancel_accepts_a_reply_without_a_body() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let returned = run(&mut CancelCapture::new(session), &mut transport)
        .expect("a no-body reply means the capture is cancelled");

    assert_eq!(returned.handle, HANDLE);
    assert_eq!(returned.next_sequence(), 1);
    assert_eq!(
        transport.sent().last(),
        Some(&frame::build_cancel_capture_mid(HANDLE)),
        "no teardown follows a successful cancel"
    );
    transport.assert_exhausted();
}

#[test]
fn a_mid_session_cancel_status_error_is_distinct_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0x0c,
        body: frame::build_plain_reply(
            cmd::CANCEL_CAPTURE,
            attr::CANCEL_SESSION,
            HANDLE,
            0x0c,
            &[],
        ),
    });
    for outcome in teardown_replies() {
        transport.push(outcome);
    }

    assert_eq!(
        run(&mut CancelCapture::new(session), &mut transport),
        Err(CancelError::SensorStatus(0x0c))
    );
    let sent = transport.sent();
    assert_eq!(sent[3], frame::build_cancel_capture_mid(HANDLE));
    assert_eq!(
        sent[4],
        frame::build_cancel_capture(HANDLE),
        "sessionless cancel"
    );
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_mid_session_cancel_transport_failure_tears_down_and_keeps_the_error() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    for outcome in teardown_replies() {
        transport.push(outcome);
    }

    assert_eq!(
        run(&mut CancelCapture::new(session), &mut transport),
        Err(CancelError::Transport(TransportError::Disconnected))
    );
    let sent = transport.sent();
    assert_eq!(sent[3], frame::build_cancel_capture_mid(HANDLE));
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn the_shipped_sequence_rule_is_the_reference_reading() {
    assert_eq!(SequenceRule::SHIPPED, SequenceRule::Reference);
}

#[test]
fn a_pending_arm_reply_then_cancel_and_rearm_uses_each_readings_sequence() {
    // `0x85` is what the reference's verify_run sees when a capture is already armed: it advances
    // the sequence, sends the mid-session cancel, and re-arms at the new number. The alternative
    // reading keeps the counter across that reply. Both go through the one predicate.
    for (rule, expected_after_pending) in [
        (SequenceRule::Reference, 2),
        (SequenceRule::CapturePendingKeepsSequence, 1),
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport).with_sequence_rule(rule);
        assert_eq!(session.next_sequence(), 1, "0x02 consumed zero");

        // The armed capture is already pending: the first 0x66 reply is 0x85 with a body.
        transport.push(ScriptedOutcome::Reply {
            status: status::CAPTURE_PENDING,
            body: capture_reply(&session, status::CAPTURE_PENDING, &[0u8; 28]),
        });
        let mut arm = ArmCapture::new(session, iv(0x50));
        let session = match run(&mut arm, &mut transport).expect("the 0x85 reply is consumed") {
            ArmOutcome::AlreadyPending(session) => session,
            other => panic!("{rule:?}: expected a pending capture, got {other:?}"),
        };
        assert_eq!(
            session.next_sequence(),
            expected_after_pending,
            "{rule:?} after a 0x85 reply"
        );

        transport.push(ScriptedOutcome::ReplyWithoutBody);
        let session = run(&mut CancelCapture::new(session), &mut transport)
            .expect("the mid-session cancel succeeds");
        assert_eq!(
            session.next_sequence(),
            expected_after_pending,
            "{rule:?}: the plain cancel does not move the counter"
        );

        let rearm_iv = iv(0x40);
        let expected_rearm = arm_frame_at(&session, &rearm_iv, expected_after_pending);
        push_arm(&mut transport, &session);
        let mut arm = ArmCapture::new(session, rearm_iv);
        let rearmed = match run(&mut arm, &mut transport).expect("the re-arm captures") {
            ArmOutcome::Armed(armed) => armed,
            other => panic!("{rule:?}: expected an armed capture, got {other:?}"),
        };

        assert_eq!(
            transport.sent()[5],
            expected_rearm,
            "{rule:?}: the re-arm carries sequence {expected_after_pending}"
        );
        assert_eq!(
            rearmed.session.next_sequence(),
            expected_after_pending + 1,
            "{rule:?}: the re-arm reply advances from there"
        );
        transport.assert_exhausted();
    }
}

#[test]
fn an_arm_only_capture_returns_without_waiting_for_the_finger() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_arm(&mut transport, &session);

    let mut arm = ArmCapture::new(session, iv(0x50));
    let armed = match run(&mut arm, &mut transport).expect("the arm reply carries the hash") {
        ArmOutcome::Armed(armed) => armed,
        other => panic!("expected an armed capture, got {other:?}"),
    };

    assert_eq!(armed.sample_hash, SAMPLE_HASH);
    assert_eq!(armed.session.handle, HANDLE);
    transport.assert_exhausted();
}

#[test]
fn a_pending_arm_returns_the_session_without_tearing_it_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: status::CAPTURE_PENDING,
        body: capture_reply(&session, status::CAPTURE_PENDING, &[0u8; 28]),
    });

    let mut arm = ArmCapture::new(session, iv(0x50));
    let session = match run(&mut arm, &mut transport).expect("a pending arm is an outcome") {
        ArmOutcome::AlreadyPending(session) => session,
        other => panic!("expected a pending capture, got {other:?}"),
    };

    assert_eq!(session.handle, HANDLE);
    assert_eq!(
        transport.sent().len(),
        4,
        "handshake, open and the arm; no teardown for a pending capture"
    );
    transport.assert_exhausted();
}

#[test]
fn an_arm_only_capture_still_tears_down_on_a_status_error() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0x0c,
        body: capture_reply(&session, 0x0c, &[0u8; 28]),
    });
    for outcome in teardown_replies() {
        transport.push(outcome);
    }

    let mut arm = ArmCapture::new(session, iv(0x50));
    assert_eq!(
        run(&mut arm, &mut transport),
        Err(CaptureError::SensorStatus(0x0c))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_verification_records_which_primitive_was_cancelled() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_arm(&mut transport, &session);
    transport.push(ScriptedOutcome::Cancelled);
    for outcome in teardown_replies() {
        transport.push(outcome);
    }

    let mut verify = Verify::new(session, iv(0x60), iv(0x70));
    assert_eq!(
        run(&mut verify, &mut transport),
        Err(VerifyError::Capture(CaptureError::Cancelled))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

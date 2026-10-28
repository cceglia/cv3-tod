//! Verification scenarios driven through the scripted transport.
//!
//! Every expected frame is built with the same codec the implementation uses, from constants
//! written out independently here: the command numbers, attributes, TLV layouts and sequence
//! numbers come from the protocol description, not from the module under test. The `0x73` request
//! is asserted byte for byte because its last TLV entry carries no value bytes at all.

mod common;

use common::{
    HANDLE, MATCH_PLAINTEXT_LEN, MATCH_TLV_LEN, MATCH_VALUE, SAMPLE_HASH, arm_frame, capture_reply,
    fixed_iv, match_frame, match_frame_at, match_plaintext, match_plaintext_with_len, match_reply,
    match_tlv, opened_session, sample_hash_plaintext,
};
use cv3_core::crypto;
use cv3_core::frame;
use cv3_core::proto::{attr, cmd};
use cv3_core::session::{CloseSession, Teardown, UnwrapError};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::verify::{Match, MatchError, Verify, VerifyError};
use cv3_core::{Action, Event, Operation, TransportError};

fn capture_iv() -> [u8; crypto::BLOCK_LEN] {
    let mut iv = [0u8; crypto::BLOCK_LEN];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x60 + index as u8;
    }
    iv
}

fn match_iv() -> [u8; crypto::BLOCK_LEN] {
    let mut iv = [0u8; crypto::BLOCK_LEN];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x80 + index as u8;
    }
    iv
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
}

fn expect_send<T: std::fmt::Debug>(action: Action<T>) -> Vec<u8> {
    match action {
        Action::Send(frame) => frame,
        other => panic!("expected a send, got {other:?}"),
    }
}

fn expect_finish<T: std::fmt::Debug>(action: Action<T>) -> T {
    match action {
        Action::Finish(value) => value,
        other => panic!("expected a finish, got {other:?}"),
    }
}

fn teardown_replies() -> [ScriptedOutcome; 2] {
    [
        ScriptedOutcome::ReplyWithoutBody,
        ScriptedOutcome::ReplyWithoutBody,
    ]
}

/// Pushes one successful capture and a finger event.
fn push_capture(transport: &mut ScriptedTransport, session: &cv3_core::Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Finger);
}

fn push_match(transport: &mut ScriptedTransport, session: &cv3_core::Session, word: u32) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(session, 0, &match_plaintext(word, Some(&MATCH_VALUE))),
    });
}

#[test]
fn a_verify_arms_waits_matches_and_reports_the_reply() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let expected_arm = arm_frame(&session, &capture_iv());
    let expected_match = match_frame_at(&session, &match_iv(), 2);

    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1);
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    let verification = run(&mut verify, &mut transport).expect("the finger matched");

    assert_eq!(verification.verdict.word, 1);
    assert!(verification.verdict.matched);
    assert_eq!(verification.verdict.value, Some(MATCH_VALUE));
    assert_eq!(verification.verdict.plaintext_len, 52);
    assert_eq!(
        verification.verdict.reply_len,
        frame::HEADER_LEN + 64,
        "52 plaintext bytes pad to 64 ciphertext bytes"
    );
    assert_eq!(verification.session.handle, HANDLE);
    assert_eq!(
        verification.session.next_sequence(),
        3,
        "0x02 consumed zero, the 0x66 reply consumed one and the 0x73 reply consumed two"
    );

    let sent = transport.sent();
    assert_eq!(
        sent.len(),
        5,
        "handshake, open, arm, match; no teardown on success"
    );
    assert_eq!(sent[3], expected_arm, "0x66 at sequence one");
    assert_eq!(sent[4], expected_match, "0x73 at sequence two");
    transport.assert_exhausted();
}

#[test]
fn the_match_frame_is_the_reference_tlv_at_plaintext_len_112() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let key = *session.key().as_bytes();
    let expected = match_frame(&session, &match_iv());

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(&session, 0, &match_plaintext(1, Some(&MATCH_VALUE))),
    });
    let mut operation = Match::new(session, match_iv());
    let verification = run(&mut operation, &mut transport).expect("the reply decodes");

    let sent = transport.sent();
    assert_eq!(sent.len(), 4);
    assert_eq!(
        sent[3], expected,
        "the whole wrapped frame is the protocol's"
    );
    let frame = &sent[3];

    assert_eq!(
        frame.len(),
        172,
        "112 plaintext bytes pad to 128 ciphertext bytes"
    );
    assert_eq!(le32(frame, 0), 1, "magic");
    assert_eq!(le32(frame, 4), 172, "total length");
    assert_eq!(&frame[8..10], &cmd::MATCH.to_le_bytes(), "0x73");
    assert_eq!(frame[10], attr::CAPTURE, "attribute 0x47");
    assert_eq!(frame[11], 0x02, "wrapped encoding");
    assert_eq!(le32(frame, 16), HANDLE, "session handle");
    assert_eq!(le32(frame, 40), MATCH_TLV_LEN as u32, "declared TLV length");

    let mut iv = [0u8; crypto::BLOCK_LEN];
    iv.copy_from_slice(&frame[24..40]);
    let plaintext = crypto::decrypt_cbc(&key, &iv, &frame[44..]).expect("the request decrypts");
    assert_eq!(plaintext.len(), MATCH_PLAINTEXT_LEN);
    assert_eq!(&plaintext[..MATCH_TLV_LEN], &match_tlv(HANDLE));
    assert!(
        plaintext[MATCH_TLV_LEN + 32..]
            .iter()
            .all(|byte| *byte == 0),
        "the rest of the plaintext is zero padding after the token"
    );
    assert_eq!(verification.verdict.plaintext_len, 52);
}

#[test]
fn a_match_reply_decodes_the_word_value_and_both_lengths() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let reply = match_reply(&session, 0, &match_plaintext(1, Some(&MATCH_VALUE)));

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: reply.clone(),
    });
    let mut operation = Match::new(session, match_iv());
    let verification = run(&mut operation, &mut transport).expect("the reply decodes");

    assert_eq!(verification.verdict.word, 1);
    assert!(verification.verdict.matched);
    assert_eq!(verification.verdict.value, Some(MATCH_VALUE));
    assert_eq!(verification.verdict.reply_len, reply.len());
    assert_eq!(verification.verdict.plaintext_len, 52);
    assert_eq!(verification.session.next_sequence(), 2);
    transport.assert_exhausted();
}

#[test]
fn a_no_match_reply_is_decoded_in_the_same_detail_even_with_the_value_present() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let reply = match_reply(&session, 0, &match_plaintext(0, Some(&MATCH_VALUE)));

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: reply.clone(),
    });
    let mut operation = Match::new(session, match_iv());
    let verification = run(&mut operation, &mut transport).expect("a no-match is a valid reply");

    assert_eq!(verification.verdict.word, 0);
    assert!(!verification.verdict.matched);
    assert_eq!(
        verification.verdict.value,
        Some(MATCH_VALUE),
        "a no-match may carry the same value; the caller must see it"
    );
    assert_eq!(verification.verdict.reply_len, reply.len());
    assert_eq!(verification.verdict.plaintext_len, 52);
}

#[test]
fn an_undefined_verdict_word_is_not_a_match_and_is_preserved() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(&session, 0, &match_plaintext(2, None)),
    });
    let mut operation = Match::new(session, match_iv());

    let verification = run(&mut operation, &mut transport).expect("the reply is well formed");
    assert_eq!(verification.verdict.word, 2);
    assert!(
        !verification.verdict.matched,
        "only verdict word 1 authenticates; an undefined word fails closed"
    );
}

#[test]
fn a_no_match_reply_without_the_value_reports_it_absent() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let reply = match_reply(&session, 0, &match_plaintext(0, None));

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: reply.clone(),
    });
    let mut operation = Match::new(session, match_iv());
    let verification = run(&mut operation, &mut transport).expect("a no-match is a valid reply");

    assert!(!verification.verdict.matched);
    assert_eq!(verification.verdict.value, None, "no 20 bytes at +32");
    assert_eq!(verification.verdict.plaintext_len, 28);
    assert_eq!(verification.verdict.reply_len, reply.len());
}

#[test]
fn a_reply_too_short_for_the_verdict_word_is_malformed_not_a_no_match() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let reply = match_reply(&session, 0, &match_plaintext_with_len(0, None, 11));

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: reply.clone(),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::MissingVerdict {
            plaintext_len: 11,
            reply_len: reply.len(),
        })
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_sensor_status_on_the_match_reply_tears_down_and_is_distinct() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0x0c,
        body: match_reply(&session, 0x0c, &[]),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::SensorStatus(0x0c))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_bad_wrap_sequence_on_the_match_is_its_own_outcome() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0x0f,
        body: match_reply(&session, 0x0f, &[]),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::WrongSequence)
    );
    transport.assert_exhausted();
}

#[test]
fn a_bodyless_match_reply_is_a_missing_reply_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::MissingReply)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn an_unwrap_failure_is_reported_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: frame::build_wrapped(
            cmd::MATCH,
            attr::CAPTURE,
            HANDLE,
            &fixed_iv(),
            0,
            &[0u8; 17],
        ),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::MalformedReply(
            UnwrapError::CiphertextNotAligned { got: 17 }
        ))
    );
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_match_command_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Cancelled);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::Cancelled)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_finger_where_the_match_reply_was_expected_is_unexpected_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Finger);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::UnexpectedEvent)
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_match_transport_failure_tears_down_and_keeps_the_transport_error() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut operation = Match::new(session, match_iv());

    assert_eq!(
        run(&mut operation, &mut transport),
        Err(MatchError::Transport(TransportError::Disconnected))
    );
    let sent = transport.sent();
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_capture_timeout_and_a_transport_error_are_distinct_and_both_tear_down() {
    // Finger timeout: the arm succeeded, the wait timed out.
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    assert_eq!(
        run(&mut verify, &mut transport),
        Err(VerifyError::Capture(cv3_core::CaptureError::FingerTimeout))
    );
    let sent = transport.sent();
    assert_eq!(sent.len(), 6, "handshake, open, arm, then cancel and close");
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();

    // A transport failure at the arm is not a finger timeout.
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    assert_eq!(
        run(&mut verify, &mut transport),
        Err(VerifyError::Capture(cv3_core::CaptureError::Transport(
            TransportError::Disconnected
        )))
    );
    let sent = transport.sent();
    assert_eq!(sent.len(), 6);
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_cancelled_verify_finger_wait_tears_down_and_is_distinct() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Cancelled);
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    assert_eq!(
        run(&mut verify, &mut transport),
        Err(VerifyError::Capture(cv3_core::CaptureError::Cancelled))
    );
    let sent = transport.sent();
    assert_eq!(sent.len(), 6);
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_match_failure_after_a_successful_capture_tears_down_once() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    transport.push(ScriptedOutcome::Reply {
        status: 0x0c,
        body: match_reply(&session, 0x0c, &[]),
    });
    transport.push(teardown_replies()[0].clone());
    transport.push(teardown_replies()[1].clone());
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    assert_eq!(
        run(&mut verify, &mut transport),
        Err(VerifyError::Match(MatchError::SensorStatus(0x0c)))
    );
    let sent = transport.sent();
    assert_eq!(
        sent.len(),
        7,
        "handshake, open, arm, match, then one cancel and one close"
    );
    assert_eq!(sent[5], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[6], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_successful_verify_leaves_the_session_open_for_the_caller_to_tear_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1);
    let mut verify = Verify::new(session, capture_iv(), match_iv());

    let verification = run(&mut verify, &mut transport).expect("the finger matched");
    assert_eq!(verification.session.handle, HANDLE);
    assert_eq!(
        transport.sent().len(),
        5,
        "a successful verify never tears the session down itself"
    );

    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    let mut teardown = Teardown::new(verification.session.handle);
    assert_eq!(run(&mut teardown, &mut transport), Ok(()));

    let sent = transport.sent();
    assert_eq!(sent[5], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[6], frame::build_close_handle(HANDLE));
    transport.assert_exhausted();
}

#[test]
fn a_finished_match_is_inert() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(&session, 0, &match_plaintext(1, Some(&MATCH_VALUE))),
    });
    let mut operation = Match::new(session, match_iv());
    let _ = run(&mut operation, &mut transport);

    assert_eq!(
        expect_finish(operation.step(Event::Cancelled)),
        Err(MatchError::AlreadyFinished)
    );
    assert_eq!(
        expect_finish(operation.start()),
        Err(MatchError::AlreadyFinished)
    );
}

#[test]
fn a_cancelled_match_sends_the_cancel_then_the_close() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let mut operation = Match::new(session, match_iv());

    let _ = operation.start();
    let cancel = expect_send(operation.step(Event::Cancelled));
    assert_eq!(cancel, frame::build_cancel_capture(HANDLE));
    let close = expect_send(operation.step(Event::ReplyWithoutBody));
    assert_eq!(close, frame::build_close_handle(HANDLE));
    assert_eq!(
        expect_finish(operation.step(Event::ReplyWithoutBody)),
        Err(MatchError::Cancelled)
    );
}

#[test]
fn a_close_after_a_successful_match_is_the_documented_frame() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1);
    let mut verify = Verify::new(session, capture_iv(), match_iv());
    let verification = run(&mut verify, &mut transport).expect("the finger matched");

    let mut close = CloseSession::new(verification.session.handle);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    assert_eq!(run(&mut close, &mut transport), Ok(()));
    assert_eq!(
        transport.sent().last(),
        Some(&frame::build_close_handle(HANDLE))
    );
}

#[test]
fn the_sample_hash_is_not_the_match_value() {
    assert_ne!(SAMPLE_HASH, MATCH_VALUE);
}

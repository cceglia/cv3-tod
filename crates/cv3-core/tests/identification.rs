//! Identification scenarios driven through the scripted transport.
//!
//! The gallery entries are built from the same fixed `CV3P` record the plugin stores, and the
//! expected request is built independently from the protocol description in `common`: the type-2
//! array must carry every candidate handle in gallery order, under the capture attribute `0x47`.
//! That attribute is what keeps this request apart from the inventory query (`0x2F` attr `0x42`),
//! which identification never sends and never depends on.

mod common;

use common::{
    HANDLE, MATCHED_HANDLE, arm_frame, capture_reply, command_frame_at_with_handles,
    match_plaintext, match_reply, opened_session, sample_hash_plaintext,
};
use cv3_core::crypto;
use cv3_core::frame;
use cv3_core::identify::{Gallery, GalleryEntry, Identify, IdentifyError, IdentifyOutcome};
use cv3_core::print::{PrintPayload, PrintSource};
use cv3_core::proto::{attr, cmd};
use cv3_core::session::UnwrapError;
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::{MatchError, Operation, VerifyError};

const FIRST_HANDLE: u32 = 0x0070_69a9;
const SECOND_HANDLE: u32 = 0x002f_1a08;

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

fn record(handle: u32) -> Vec<u8> {
    PrintPayload::bound([0xa5; 20], PrintSource::EnrolmentId, handle)
        .encode()
        .to_vec()
}

fn gallery(payloads: &[Vec<u8>]) -> Gallery {
    let entries: Vec<GalleryEntry<'_>> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| GalleryEntry::new(index, payload))
        .collect();
    Gallery::from_entries(&entries)
}

fn push_capture(transport: &mut ScriptedTransport, session: &cv3_core::Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Finger);
}

fn push_match(
    transport: &mut ScriptedTransport,
    session: &cv3_core::Session,
    word: u32,
    handle: u32,
) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: match_reply(session, 0, &match_plaintext(word, Some(handle))),
    });
}

fn push_teardown(transport: &mut ScriptedTransport) {
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
}

#[test]
fn a_gallery_of_two_prints_sends_both_handles_and_returns_the_one_that_matched() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let expected_arm = arm_frame(&session, &capture_iv());
    let expected = command_frame_at_with_handles(
        &session,
        cmd::IDENTIFY_HANDLES,
        &match_iv(),
        2,
        &[FIRST_HANDLE, SECOND_HANDLE],
        None,
    );

    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1, SECOND_HANDLE);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE), record(SECOND_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("the second print matched");

    match outcome {
        IdentifyOutcome::Matched {
            index,
            verdict,
            session,
        } => {
            assert_eq!(index, 1, "the exact gallery print, not merely some print");
            assert_eq!(verdict.matched_handle, Some(SECOND_HANDLE));
            assert_eq!(verdict.word, 1);
            assert_eq!(session.handle, HANDLE);
            assert_eq!(
                session.next_sequence(),
                3,
                "0x02 consumed zero, the arm one and the match two"
            );
        }
        other => panic!("expected a match, got {other:?}"),
    }

    let sent = transport.sent();
    assert_eq!(
        sent.len(),
        5,
        "handshake, open, arm, one match; no teardown"
    );
    assert_eq!(sent[3], expected_arm, "0x66 at one");
    assert_eq!(
        sent[4], expected,
        "one 0x2F whose type-2 array carries both gallery handles"
    );
    assert_eq!(
        sent[4][10],
        attr::CAPTURE,
        "the request is the match form (attr 0x47), not the inventory query (0x42)"
    );
    transport.assert_exhausted();
}

#[test]
fn a_match_for_a_handle_outside_the_gallery_is_a_no_match() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1, 0x0bad_f00d);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("the sensor answered");

    match outcome {
        IdentifyOutcome::NoMatch { verdict, session } => {
            assert_eq!(verdict.word, 1);
            assert_eq!(verdict.matched_handle, Some(0x0bad_f00d));
            assert_eq!(session.handle, HANDLE, "the session is still open");
        }
        other => panic!("expected a no-match, got {other:?}"),
    }
    assert_eq!(
        transport.sent().len(),
        5,
        "an answered no-match is not a failure and does not tear down"
    );
}

#[test]
fn a_zero_verdict_is_a_no_match() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 0, 0);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("the sensor answered");

    assert!(matches!(outcome, IdentifyOutcome::NoMatch { .. }));
}

#[test]
fn an_empty_gallery_is_a_no_match_without_a_capture_or_a_command() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let mut identify = Identify::new(session, Gallery::default(), capture_iv(), match_iv());

    let outcome = run(&mut identify, &mut transport).expect("nothing to do is not an error");

    match outcome {
        IdentifyOutcome::EmptyGallery { session } => {
            assert_eq!(session.handle, HANDLE, "the session is untouched");
        }
        other => panic!("expected an empty gallery, got {other:?}"),
    }
    assert_eq!(
        transport.sent().len(),
        3,
        "handshake and open only: no capture was armed"
    );
    transport.assert_exhausted();
}

#[test]
fn a_gallery_of_unusable_records_is_a_no_match_without_a_capture() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let mut unbound = record(FIRST_HANDLE);
    unbound[5] &= !0x01;
    let mut foreign = record(SECOND_HANDLE);
    foreign[0] = b'X';
    let mut other_version = record(SECOND_HANDLE);
    other_version[4] = 2;
    let mut identify = Identify::new(
        session,
        gallery(&[Vec::new(), unbound, foreign, other_version]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("nothing to do is not an error");

    assert!(matches!(outcome, IdentifyOutcome::EmptyGallery { .. }));
    assert_eq!(transport.sent().len(), 3, "no 0x66 and no 0x2F");
}

#[test]
fn a_duplicated_handle_is_never_a_candidate_for_either_print() {
    // Both prints name the same template: the reply could not say which print it meant.
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE), record(FIRST_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("an ambiguous gallery is no match");

    assert!(matches!(outcome, IdentifyOutcome::EmptyGallery { .. }));
    assert_eq!(transport.sent().len(), 3, "the sensor was not asked");

    // A unique print next to a duplicated pair remains a candidate at its own index.
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1, FIRST_HANDLE);
    let mut identify = Identify::new(
        session,
        gallery(&[
            record(FIRST_HANDLE),
            record(FIRST_HANDLE),
            record(SECOND_HANDLE),
        ]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("the sensor answered");

    match outcome {
        IdentifyOutcome::NoMatch { session, .. } => {
            assert_eq!(session.handle, HANDLE, "the session is still open");
        }
        other => panic!("a duplicated handle must not match: {other:?}"),
    }
}

#[test]
fn the_unique_print_next_to_a_duplicated_pair_still_matches_at_its_own_index() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    push_match(&mut transport, &session, 1, SECOND_HANDLE);
    let mut identify = Identify::new(
        session,
        gallery(&[
            record(FIRST_HANDLE),
            record(FIRST_HANDLE),
            record(SECOND_HANDLE),
        ]),
        capture_iv(),
        match_iv(),
    );

    let outcome = run(&mut identify, &mut transport).expect("the unique print matched");

    match outcome {
        IdentifyOutcome::Matched { index, .. } => {
            assert_eq!(index, 2, "the gallery position of the unique print");
        }
        other => panic!("expected a match, got {other:?}"),
    }
}

#[test]
fn a_reply_that_does_not_decrypt_is_an_error_not_a_no_match() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_capture(&mut transport, &session);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: frame::build_wrapped(
            cmd::IDENTIFY_HANDLES,
            attr::CAPTURE,
            HANDLE,
            &[0u8; 16],
            0,
            &[0u8; 17],
        ),
    });
    push_teardown(&mut transport);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    assert_eq!(
        run(&mut identify, &mut transport),
        Err(IdentifyError::Verify(VerifyError::Match(
            MatchError::MalformedReply(UnwrapError::CiphertextNotAligned { got: 17 })
        )))
    );
    let sent = transport.sent();
    assert_eq!(
        sent[sent.len() - 2],
        frame::build_cancel_capture(HANDLE),
        "the match's teardown ran"
    );
    assert_eq!(sent[sent.len() - 1], frame::build_close_handle(HANDLE));
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
    push_teardown(&mut transport);
    let mut identify = Identify::new(
        session,
        gallery(&[record(FIRST_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    assert_eq!(
        run(&mut identify, &mut transport),
        Err(IdentifyError::Verify(VerifyError::Capture(
            cv3_core::CaptureError::Cancelled
        )))
    );
    let sent = transport.sent();
    assert_eq!(
        sent.len(),
        6,
        "handshake, open, arm, cancel, close (the cancelled wait sent nothing)"
    );
    assert_eq!(sent[4], frame::build_cancel_capture(HANDLE));
    assert_eq!(sent[5], frame::build_close_handle(HANDLE));
}

#[test]
fn an_identify_that_never_started_reports_an_unexpected_event() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let mut identify = Identify::new(
        session,
        gallery(&[record(MATCHED_HANDLE)]),
        capture_iv(),
        match_iv(),
    );

    assert_eq!(
        identify.step(cv3_core::Event::Finger),
        cv3_core::Action::Finish(Err(IdentifyError::UnexpectedEvent))
    );
}

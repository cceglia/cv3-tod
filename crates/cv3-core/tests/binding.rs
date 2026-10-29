//! Whole-enrolment scenarios driven through the scripted transport.
//!
//! Every expected frame is built from constants written out independently here: command numbers,
//! attributes, TLV layouts and the match reply's measured shape come from the protocol
//! description, not from the module under test.

mod common;

use common::{HANDLE, SAMPLE_HASH, fixed_iv, opened_session, sample_hash_plaintext};
use cv3_core::bind::{
    BindError, BoundEnrolment, ENROL_STAGES, EnrolAndBind, EnrolFailure, EnrolStages,
    TEMPLATE_MAY_REMAIN,
};
use cv3_core::crypto::{self, BLOCK_LEN, SESSION_KEY_LEN};
use cv3_core::enrol::MAX_ACCEPTED_SAMPLES;
use cv3_core::frame;
use cv3_core::print::{PRINT_PAYLOAD_LEN, PrintSource};
use cv3_core::proto::{attr, cmd, status};
use cv3_core::session::{Session, SessionKey};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, Transport};
use cv3_core::verify::Verdict;
use cv3_core::{Action, Event, Operation, TransportError};

/// The 20-byte enrolment id the sensor reports when it completes. Different from `SAMPLE_HASH`.
const ENROLMENT_ID: [u8; 20] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3,
];
/// The template handle the commit reply names on 2026-10-29.
const COMMIT_HANDLE: u32 = 0x00f2_361f;

fn base_iv() -> [u8; BLOCK_LEN] {
    let mut iv = [0u8; BLOCK_LEN];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x40 + index as u8;
    }
    iv
}

fn confirmation_capture_iv() -> [u8; BLOCK_LEN] {
    [0x60; BLOCK_LEN]
}

fn match_iv() -> [u8; BLOCK_LEN] {
    [0x70; BLOCK_LEN]
}

/// The session key for the deterministic fixtures, derived through a throwaway open.
fn sensor_key() -> [u8; SESSION_KEY_LEN] {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    *session.key().as_bytes()
}

fn wrapped_reply(
    key: &[u8; SESSION_KEY_LEN],
    command: u16,
    attribute: u8,
    command_status: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let iv = fixed_iv();
    let ciphertext = crypto::encrypt_cbc(key, &iv, plaintext);
    let mut body = frame::build_wrapped(
        command,
        attribute,
        HANDLE,
        &iv,
        plaintext.len() as u32,
        &ciphertext,
    );
    body[20..24].copy_from_slice(&command_status.to_le_bytes());
    body
}

/// `(u32 tag 0, u32 length 20, value)`, the one entry an accepted sample's reply carries.
fn twenty_byte_tlv(value: &[u8; 20]) -> Vec<u8> {
    let mut plaintext = vec![0u8; 8 + value.len()];
    plaintext[4..8].copy_from_slice(&(value.len() as u32).to_le_bytes());
    plaintext[8..].copy_from_slice(value);
    plaintext
}

/// The measured `0x6e` reply: `(3,0)` then `(0,4,handle)`.
fn commit_plaintext(handle: u32) -> Vec<u8> {
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&4u32.to_le_bytes());
    plaintext.extend_from_slice(&handle.to_le_bytes());
    plaintext
}

fn push_discard(transport: &mut ScriptedTransport, key: &[u8; SESSION_KEY_LEN]) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(key, cmd::DISCARD_ENROLMENT, attr::SESSION, 0, &[]),
    });
}

fn push_start(transport: &mut ScriptedTransport) {
    transport.push(ScriptedOutcome::ReplyWithoutBody);
}

/// One accepted sample: the arm reply, the finger event and the `0x6c` reply.
fn push_sample(
    transport: &mut ScriptedTransport,
    key: &[u8; SESSION_KEY_LEN],
    update_status: u32,
    template_id: Option<&[u8; 20]>,
) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(
            key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            0,
            &sample_hash_plaintext(),
        ),
    });
    transport.push(ScriptedOutcome::Finger);
    let value = template_id.unwrap_or(&SAMPLE_HASH);
    transport.push(ScriptedOutcome::Reply {
        status: update_status,
        body: wrapped_reply(
            key,
            cmd::UPDATE_ENROLMENT,
            attr::SESSION,
            update_status,
            &twenty_byte_tlv(value),
        ),
    });
}

fn push_commit(transport: &mut ScriptedTransport, key: &[u8; SESSION_KEY_LEN], plaintext: &[u8]) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(key, cmd::COMMIT_ENROLMENT, attr::SESSION, 0, plaintext),
    });
}

/// The confirmation touch, then a match reply with `word` and `handle`.
fn push_confirmation(
    transport: &mut ScriptedTransport,
    key: &[u8; SESSION_KEY_LEN],
    word: u32,
    handle: u32,
) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(
            key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            0,
            &sample_hash_plaintext(),
        ),
    });
    transport.push(ScriptedOutcome::Finger);
    let mut plaintext = vec![0u8; 12 + 12 + 32];
    plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
    plaintext[8..12].copy_from_slice(&word.to_le_bytes());
    plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
    plaintext[20..24].copy_from_slice(&handle.to_le_bytes());
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(key, cmd::IDENTIFY_HANDLES, attr::CAPTURE, 0, &plaintext),
    });
}

fn push_teardown(transport: &mut ScriptedTransport) {
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
}

fn sent_commands(transport: &ScriptedTransport) -> Vec<u16> {
    transport
        .sent()
        .iter()
        .map(|frame| u16::from_le_bytes([frame[8], frame[9]]))
        .collect()
}

/// Drives the operation and records the stage snapshot after every step.
fn drive(
    operation: &mut EnrolAndBind,
    transport: &mut ScriptedTransport,
) -> (Result<BoundEnrolment, EnrolFailure>, Vec<EnrolStages>) {
    let mut action = operation.start();
    let mut seen = Vec::new();
    loop {
        match action {
            Action::Send(frame) => action = operation.step(transport.command(&frame)),
            Action::WaitFinger => action = operation.step(transport.wait_finger()),
            Action::Finish(result) => {
                seen.push(operation.stages());
                return (result, seen);
            }
        }
        seen.push(operation.stages());
    }
}

fn enrol_and_bind(
    transport: &mut ScriptedTransport,
    session: Session,
) -> (Result<BoundEnrolment, EnrolFailure>, Vec<EnrolStages>) {
    let mut operation =
        EnrolAndBind::new(session, base_iv(), confirmation_capture_iv(), match_iv());
    drive(&mut operation, transport)
}

#[test]
fn an_early_completion_binds_the_print_in_three_stages() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::SAMPLE_ACCEPTED, None);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let (outcome, stages) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let bound = outcome.expect("the confirmation matches, so the print is bound");

    assert_eq!(bound.template_id, ENROLMENT_ID);
    assert_eq!(bound.source, PrintSource::EnrolmentId);
    assert_eq!(bound.accepted_samples, 2);
    assert_eq!(bound.match_id, COMMIT_HANDLE);
    assert_eq!(bound.session.handle, HANDLE, "the session stays open");
    assert_eq!(
        sent_commands(&transport),
        [
            cmd::CHALLENGE,
            cmd::CHALLENGE_RESPONSE,
            cmd::OPEN_SESSION,
            cmd::DISCARD_ENROLMENT,
            cmd::START_ENROLMENT,
            cmd::ARM_CAPTURE,
            cmd::UPDATE_ENROLMENT,
            cmd::ARM_CAPTURE,
            cmd::UPDATE_ENROLMENT,
            cmd::COMMIT_ENROLMENT,
            cmd::ARM_CAPTURE,
            cmd::IDENTIFY_HANDLES,
        ],
        "two samples, the commit, then one confirmation arm and one 0x2f"
    );

    let last = stages.last().expect("a final stage snapshot");
    assert_eq!(last.accepted_samples, 2);
    assert_eq!(last.completed(), 3, "two samples and the confirmation");
    assert!(last.confirmed);
    for seen in &stages {
        assert!(
            seen.completed() <= ENROL_STAGES,
            "reported {} stages of at most {ENROL_STAGES}",
            seen.completed()
        );
    }
}

#[test]
fn twelve_samples_and_the_confirmation_are_thirteen_stages_and_never_more() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    for _ in 0..MAX_ACCEPTED_SAMPLES {
        push_sample(&mut transport, &key, status::SAMPLE_ACCEPTED, None);
    }
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let (outcome, stages) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let bound = outcome.expect("twelve samples and a confirmation bind");
    assert_eq!(bound.accepted_samples, MAX_ACCEPTED_SAMPLES);
    assert_eq!(bound.source, PrintSource::SampleHash);
    assert_eq!(bound.payload.source(), PrintSource::SampleHash);

    let last = stages.last().expect("a final stage snapshot");
    assert_eq!(last.completed(), ENROL_STAGES);
    for seen in &stages {
        assert!(
            seen.completed() <= ENROL_STAGES,
            "a snapshot reported {} > {ENROL_STAGES}",
            seen.completed()
        );
    }
}

#[test]
fn a_rejected_sample_is_retried_without_advancing_progress() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::SAMPLE_ACCEPTED, None);
    push_sample(&mut transport, &key, status::RESCAN_A, None);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let (outcome, stages) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let bound = outcome.expect("the rejected sample is retried, not fatal");
    assert_eq!(bound.accepted_samples, 2);

    assert!(
        stages
            .iter()
            .any(|seen| seen.rejected_samples == 1 && seen.accepted_samples == 1),
        "the rescan is visible while the accepted count stays put: {stages:?}"
    );
    let last = stages.last().expect("a final snapshot");
    assert_eq!(last.rejected_samples, 1);
    assert_eq!(last.capture_attempts, 3, "the rescan consumed an arm");
    assert_eq!(last.completed(), 3);
}

#[test]
fn a_confirmation_no_match_stores_no_print_and_keeps_the_session() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 0, 0);

    let (outcome, stages) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("a no-match cannot bind the print");
    assert_eq!(
        failure.error,
        BindError::ConfirmationRejected {
            word: 0,
            matched_handle: Some(0),
            expected_handle: COMMIT_HANDLE,
            reply_len: 108,
        }
    );
    assert_eq!(
        failure.session.expect("the session is still usable").handle,
        HANDLE
    );
    assert!(!stages.last().expect("a final snapshot").confirmed);
    assert!(failure.error.may_have_stored_template());
    let text = failure.error.to_string();
    assert!(text.contains("did not match"), "{text}");
    assert!(text.contains(TEMPLATE_MAY_REMAIN), "{text}");
}

#[test]
fn a_confirmation_that_matches_another_handle_is_refused() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, 0x002f_1a08);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("a different template's handle is not a match");
    assert_eq!(
        failure.error,
        BindError::ConfirmationRejected {
            word: 1,
            matched_handle: Some(0x002f_1a08),
            expected_handle: COMMIT_HANDLE,
            reply_len: 108,
        }
    );
    assert!(failure.session.is_some(), "the session survives a refusal");
    assert!(failure.error.to_string().contains(TEMPLATE_MAY_REMAIN));
}

#[test]
fn a_confirmation_that_never_happens_fails_and_names_the_remaining_template() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    // The confirmation arm is answered, then the finger never arrives.
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            0,
            &sample_hash_plaintext(),
        ),
    });
    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    push_teardown(&mut transport);

    let (outcome, stages) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("a confirmation that never happens cannot bind");
    assert_eq!(
        failure.error,
        BindError::Confirmation(cv3_core::VerifyError::Capture(
            cv3_core::CaptureError::FingerTimeout
        ))
    );
    assert!(failure.error.to_string().contains(TEMPLATE_MAY_REMAIN));
    assert_eq!(
        failure.session, None,
        "the confirmation tore the session down"
    );
    assert!(!stages.last().expect("a final snapshot").confirmed);
    assert_eq!(
        sent_commands(&transport).last(),
        Some(&cmd::CLOSE_SESSION),
        "the failed confirmation still closes the handle"
    );
}

#[test]
fn a_commit_without_a_handle_stores_no_print_and_keeps_the_session() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    // The commit succeeded but named no `(0,4,…)` handle, as the first hardware run did.
    push_commit(&mut transport, &key, &[]);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("nothing can be matched without a handle");
    assert_eq!(failure.error, BindError::NoCommitHandle);
    assert_eq!(
        failure.session.expect("the session is still usable").handle,
        HANDLE
    );
    let text = failure.error.to_string();
    assert!(text.contains("0x6e"), "{text}");
    assert!(text.contains(TEMPLATE_MAY_REMAIN), "{text}");
    assert!(
        !sent_commands(&transport).contains(&cmd::IDENTIFY_HANDLES),
        "no confirmation is attempted without a handle"
    );
}

#[test]
fn a_cancelled_confirmation_leaves_no_print_and_says_the_template_may_remain() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            0,
            &sample_hash_plaintext(),
        ),
    });
    transport.push(ScriptedOutcome::Cancelled);
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("a cancelled confirmation binds nothing");
    assert_eq!(
        failure.error,
        BindError::Confirmation(cv3_core::VerifyError::Capture(
            cv3_core::CaptureError::Cancelled
        ))
    );
    assert!(failure.error.to_string().contains(TEMPLATE_MAY_REMAIN));
    assert!(!sent_commands(&transport).contains(&cmd::IDENTIFY_HANDLES));
}

#[test]
fn a_cancelled_sample_collection_binds_nothing_and_says_the_template_may_remain() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(
            &key,
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            0,
            &sample_hash_plaintext(),
        ),
    });
    transport.push(ScriptedOutcome::Cancelled);
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("a cancelled collection binds nothing");
    assert_eq!(
        failure.error,
        BindError::Enrol(cv3_core::EnrolError::Cancelled {
            stage: cv3_core::EnrolStage::Capture,
        })
    );
    assert!(
        failure.error.to_string().contains(TEMPLATE_MAY_REMAIN),
        "a cancelled enrolment says the same about the sensor: {}",
        failure.error
    );
    assert!(!sent_commands(&transport).contains(&cmd::COMMIT_ENROLMENT));
}

#[test]
fn a_transport_failure_at_each_confirmation_state_is_reported() {
    // The confirmation arm's command write.
    {
        let key = sensor_key();
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard(&mut transport, &key);
        push_start(&mut transport);
        push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
        push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
        transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
        push_teardown(&mut transport);

        let (outcome, _) = enrol_and_bind(&mut transport, session);
        transport.assert_exhausted();
        let failure = outcome.expect_err("the arm transfer failed");
        assert_eq!(
            failure.error,
            BindError::Confirmation(cv3_core::VerifyError::Capture(
                cv3_core::CaptureError::Transport(TransportError::Disconnected)
            ))
        );
        assert!(failure.error.to_string().contains(TEMPLATE_MAY_REMAIN));
    }

    // The confirmation match request after the finger event.
    {
        let key = sensor_key();
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard(&mut transport, &key);
        push_start(&mut transport);
        push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
        push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
        transport.push(ScriptedOutcome::Reply {
            status: 0,
            body: wrapped_reply(
                &key,
                cmd::ARM_CAPTURE,
                attr::CAPTURE,
                0,
                &sample_hash_plaintext(),
            ),
        });
        transport.push(ScriptedOutcome::Finger);
        transport.push(ScriptedOutcome::Transport(TransportError::Stall));
        push_teardown(&mut transport);

        let (outcome, _) = enrol_and_bind(&mut transport, session);
        transport.assert_exhausted();
        let failure = outcome.expect_err("the match transfer failed");
        assert_eq!(
            failure.error,
            BindError::Confirmation(cv3_core::VerifyError::Match(
                cv3_core::MatchError::Transport(TransportError::Stall)
            ))
        );
        assert!(failure.error.to_string().contains(TEMPLATE_MAY_REMAIN));
    }
}

#[test]
fn a_transport_failure_before_the_commit_is_an_enrolment_failure_with_no_session() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard(&mut transport, &key);
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    transport.assert_exhausted();
    let failure = outcome.expect_err("the start transfer failed");
    assert!(matches!(failure.error, BindError::Enrol(_)));
    assert_eq!(failure.session, None);
}

#[test]
fn the_confirmation_asks_the_sensor_for_the_commit_handle() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    outcome.expect("the print binds");
    transport.assert_exhausted();

    let request = transport
        .sent()
        .iter()
        .rfind(|frame| u16::from_le_bytes([frame[8], frame[9]]) == cmd::IDENTIFY_HANDLES)
        .expect("the confirmation request");
    let session_key = SessionKey::from_bytes(key);
    let plaintext = session_key
        .unwrap(request)
        .expect("the request decrypts")
        .plaintext;

    assert_eq!(
        &plaintext[..56],
        &common::match_tlv(HANDLE, &[COMMIT_HANDLE], None)[..56],
        "the vendor's parameter list names the commit handle"
    );
    assert_eq!(
        &plaintext[56..60],
        &COMMIT_HANDLE.to_le_bytes(),
        "the type-2 array carries the commit reply's handle"
    );
}

#[test]
fn the_payload_is_the_thirty_byte_cv3p_record_for_the_enrolment() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let (outcome, _) = enrol_and_bind(&mut transport, session);
    let bound = outcome.expect("the print binds");
    let bytes = bound.payload_bytes();

    assert_eq!(bytes.len(), PRINT_PAYLOAD_LEN);
    let mut expected = Vec::new();
    expected.extend_from_slice(b"CV3P");
    expected.push(1);
    expected.push(0x01);
    expected.extend_from_slice(&ENROLMENT_ID);
    expected.extend_from_slice(&COMMIT_HANDLE.to_le_bytes());
    assert_eq!(bytes.to_vec(), expected, "the stored record is pinned");
    assert!(bound.payload.accepts(&Verdict {
        command: cmd::IDENTIFY_HANDLES,
        status: status::OK,
        word: 1,
        matched: true,
        matched_handle: Some(COMMIT_HANDLE),
        plaintext: Some({
            let mut plaintext = vec![0u8; 56];
            plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
            plaintext[8..12].copy_from_slice(&1u32.to_le_bytes());
            plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
            plaintext[20..24].copy_from_slice(&COMMIT_HANDLE.to_le_bytes());
            plaintext
        }),
        plaintext_len: 56,
        reply_len: 108,
    }));
}

#[test]
fn a_finished_enrolment_is_inert_and_does_not_panic() {
    let key = sensor_key();
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard(&mut transport, &key);
    push_start(&mut transport);
    push_sample(&mut transport, &key, status::OK, Some(&ENROLMENT_ID));
    push_commit(&mut transport, &key, &commit_plaintext(COMMIT_HANDLE));
    push_confirmation(&mut transport, &key, 1, COMMIT_HANDLE);

    let mut operation =
        EnrolAndBind::new(session, base_iv(), confirmation_capture_iv(), match_iv());
    let (outcome, _) = drive(&mut operation, &mut transport);
    outcome.expect("the print binds");

    assert_eq!(
        operation.step(Event::Finger),
        Action::Finish(Err(EnrolFailure {
            error: BindError::AlreadyFinished,
            session: None,
        }))
    );
    assert!(matches!(
        operation.start(),
        Action::Finish(Err(EnrolFailure {
            error: BindError::AlreadyFinished,
            ..
        }))
    ));
    assert_eq!(operation.stages().completed(), 2);
}

#[test]
fn the_stage_count_is_thirteen() {
    assert_eq!(ENROL_STAGES, 13);
    assert_eq!(ENROL_STAGES, MAX_ACCEPTED_SAMPLES + 1);
    let stages = EnrolStages {
        accepted_samples: MAX_ACCEPTED_SAMPLES,
        capture_attempts: MAX_ACCEPTED_SAMPLES,
        rejected_samples: 0,
        confirmed: true,
    };
    assert_eq!(stages.completed(), 13);
    let over = EnrolStages {
        accepted_samples: MAX_ACCEPTED_SAMPLES + 4,
        capture_attempts: 0,
        rejected_samples: 0,
        confirmed: true,
    };
    assert_eq!(
        over.completed(),
        13,
        "a report never exceeds the declared count"
    );
}

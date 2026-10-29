//! Enrolment scenarios driven through the scripted transport.
//!
//! Every expected frame is built with the same codec the implementation uses, from constants
//! written out independently in this file: the command numbers, attributes, TLV layouts and
//! sequence numbers come from the protocol description, not from the module under test.

mod common;

use common::{HANDLE, SAMPLE_HASH, capture_reply, fixed_iv, opened_session, sample_hash_plaintext};
use cv3_core::crypto;
use cv3_core::enrol::{
    COMMIT_PLAINTEXT_LEN, COMMIT_TLV_LEN, DISCARD_PLAINTEXT_LEN, DISCARD_TLV_LEN, Enrol,
    EnrolError, EnrolProgress, EnrolStage, EnrolledTemplate, MAX_ACCEPTED_SAMPLES,
    MAX_CAPTURE_ATTEMPTS, START_TLV_LEN, TemplateSource, UPDATE_PLAINTEXT_LEN, UPDATE_TLV_LEN,
    commit_tlv, discard_tlv, enrol_iv, start_tlv, update_tlv,
};
use cv3_core::frame::{self, FrameError};
use cv3_core::proto::{attr, cmd, status};
use cv3_core::session::{Session, UnwrapError};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, Transport};
use cv3_core::{Action, Event, Operation, TransportError};

/// The 20-byte id the sensor returns when the enrolment completes. Deliberately different from
/// [`SAMPLE_HASH`] in every byte.
const ENROLMENT_ID: [u8; 20] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3,
];

/// The random base IV the probe hands the operation; the operation derives one IV per frame.
fn base_iv() -> [u8; crypto::BLOCK_LEN] {
    let mut iv = [0u8; crypto::BLOCK_LEN];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x40 + index as u8;
    }
    iv
}

/// A decrypted TLV carrying one 20-byte value: `(u32 tag 0, u32 length 20, value)`.
fn twenty_byte_tlv(value: &[u8; 20]) -> Vec<u8> {
    let mut plaintext = vec![0u8; 8 + value.len()];
    plaintext[4..8].copy_from_slice(&(value.len() as u32).to_le_bytes());
    plaintext[8..].copy_from_slice(value);
    plaintext
}

/// A wrapped reply with `status` at header offset 20 and `plaintext` inside the ciphertext.
fn wrapped_reply(
    session: &Session,
    command: u16,
    attribute: u8,
    command_status: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let iv = fixed_iv();
    let ciphertext = crypto::encrypt_cbc(session.key().as_bytes(), &iv, plaintext);
    let mut body = frame::build_wrapped(
        command,
        attribute,
        session.handle,
        &iv,
        plaintext.len() as u32,
        &ciphertext,
    );
    body[20..24].copy_from_slice(&command_status.to_le_bytes());
    body
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
}

fn sent_commands(transport: &ScriptedTransport) -> Vec<u16> {
    transport
        .sent()
        .iter()
        .map(|frame| u16::from_le_bytes([frame[8], frame[9]]))
        .collect()
}

fn push_discard_reply(transport: &mut ScriptedTransport, session: &Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(session, cmd::DISCARD_ENROLMENT, attr::SESSION, 0, &[]),
    });
}

fn push_start_reply(transport: &mut ScriptedTransport) {
    transport.push(ScriptedOutcome::ReplyWithoutBody);
}

fn push_arm(transport: &mut ScriptedTransport, session: &Session) {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Finger);
}

fn push_update(
    transport: &mut ScriptedTransport,
    session: &Session,
    command_status: u32,
    plaintext: &[u8],
) {
    transport.push(ScriptedOutcome::Reply {
        status: command_status,
        body: wrapped_reply(
            session,
            cmd::UPDATE_ENROLMENT,
            attr::SESSION,
            command_status,
            plaintext,
        ),
    });
}

fn push_accepted_update(transport: &mut ScriptedTransport, session: &Session) {
    push_update(
        transport,
        session,
        status::SAMPLE_ACCEPTED,
        &twenty_byte_tlv(&SAMPLE_HASH),
    );
}

fn push_completion(transport: &mut ScriptedTransport, session: &Session) {
    push_update(
        transport,
        session,
        status::OK,
        &twenty_byte_tlv(&ENROLMENT_ID),
    );
}

fn push_commit_reply(transport: &mut ScriptedTransport, session: &Session, command_status: u32) {
    transport.push(ScriptedOutcome::Reply {
        status: command_status,
        body: wrapped_reply(
            session,
            cmd::COMMIT_ENROLMENT,
            attr::SESSION,
            command_status,
            &[],
        ),
    });
}

fn push_teardown(transport: &mut ScriptedTransport) {
    transport.push(ScriptedOutcome::ReplyWithoutBody);
    transport.push(ScriptedOutcome::ReplyWithoutBody);
}

fn assert_teardown(transport: &ScriptedTransport) {
    let sent = transport.sent();
    assert!(sent.len() >= 2, "a failure must tear down");
    assert_eq!(
        sent[sent.len() - 2],
        frame::build_cancel_capture(HANDLE),
        "the sessionless cancel precedes the close"
    );
    assert_eq!(sent[sent.len() - 1], frame::build_close_handle(HANDLE));
}

/// Drives an operation one event at a time and records the progress after every step.
fn drive_with_progress(
    operation: &mut Enrol,
    transport: &mut ScriptedTransport,
) -> (Result<EnrolledTemplate, EnrolError>, Vec<EnrolProgress>) {
    let mut action = operation.start();
    let mut seen = Vec::new();
    loop {
        match action {
            Action::Send(frame) => action = operation.step(transport.command(&frame)),
            Action::WaitFinger => action = operation.step(transport.wait_finger()),
            Action::Finish(result) => {
                seen.push(operation.progress());
                return (result, seen);
            }
        }
        seen.push(operation.progress());
    }
}

fn enrol_and_drive(
    transport: &mut ScriptedTransport,
    session: Session,
) -> (Result<EnrolledTemplate, EnrolError>, Vec<EnrolProgress>) {
    let mut enrol = Enrol::new(session, base_iv());
    drive_with_progress(&mut enrol, transport)
}

#[test]
fn a_completed_enrolment_sends_the_discard_start_sample_and_commit_frames() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);

    let mut expected = vec![
        session
            .wrap(
                cmd::DISCARD_ENROLMENT,
                attr::SESSION,
                &discard_tlv(HANDLE),
                DISCARD_PLAINTEXT_LEN,
                &enrol_iv(&base_iv(), 0),
                1,
            )
            .expect("discard frame"),
        frame::build_plain(cmd::START_ENROLMENT, attr::ENROLMENT_START, 0, &start_tlv()),
    ];
    let mut outcomes = vec![
        ScriptedOutcome::Reply {
            status: 0,
            body: wrapped_reply(&session, cmd::DISCARD_ENROLMENT, attr::SESSION, 0, &[]),
        },
        ScriptedOutcome::ReplyWithoutBody,
    ];

    // Two accepted samples; the second update reply carries the enrolment id.
    let mut index = 1u32;
    let mut sequence = 2u32;
    for sample in 1..=2u32 {
        expected.push(
            session
                .wrap(
                    cmd::ARM_CAPTURE,
                    attr::CAPTURE,
                    &common::capture_tlv(HANDLE),
                    80,
                    &enrol_iv(&base_iv(), index),
                    sequence,
                )
                .expect("arm frame"),
        );
        index += 1;
        sequence += 1;
        outcomes.push(ScriptedOutcome::Reply {
            status: 0,
            body: capture_reply(&session, 0, &sample_hash_plaintext()),
        });
        outcomes.push(ScriptedOutcome::Finger);

        let id = if sample == 2 {
            ENROLMENT_ID
        } else {
            SAMPLE_HASH
        };
        expected.push(
            session
                .wrap(
                    cmd::UPDATE_ENROLMENT,
                    attr::SESSION,
                    &update_tlv(HANDLE, &SAMPLE_HASH),
                    UPDATE_PLAINTEXT_LEN,
                    &enrol_iv(&base_iv(), index),
                    sequence,
                )
                .expect("update frame"),
        );
        index += 1;
        sequence += 1;
        outcomes.push(ScriptedOutcome::Reply {
            status: status::SAMPLE_ACCEPTED,
            body: wrapped_reply(
                &session,
                cmd::UPDATE_ENROLMENT,
                attr::SESSION,
                status::SAMPLE_ACCEPTED,
                &twenty_byte_tlv(&id),
            ),
        });
    }

    expected.push(
        session
            .wrap(
                cmd::COMMIT_ENROLMENT,
                attr::SESSION,
                &commit_tlv(HANDLE, &ENROLMENT_ID),
                COMMIT_PLAINTEXT_LEN,
                &enrol_iv(&base_iv(), index),
                sequence,
            )
            .expect("commit frame"),
    );
    outcomes.push(ScriptedOutcome::Reply {
        status: 0,
        body: wrapped_reply(&session, cmd::COMMIT_ENROLMENT, attr::SESSION, 0, &[]),
    });

    for outcome in outcomes {
        transport.push(outcome);
    }
    let (outcome, progress) = enrol_and_drive(&mut transport, session);
    let template = outcome.expect("the enrolment completes");
    transport.assert_exhausted();

    assert_eq!(template.template_id, ENROLMENT_ID);
    assert_eq!(template.source, TemplateSource::EnrolmentId);
    assert_eq!(template.accepted_samples, 2);
    assert_eq!(template.session.handle, HANDLE, "the session stays open");
    assert_eq!(
        template.session.next_sequence(),
        7,
        "the commit reply advances the wrap sequence"
    );

    let sent = &transport.sent()[3..];
    assert_eq!(sent, expected, "the exact frame sequence");
    assert_wrapped(
        &sent[0],
        cmd::DISCARD_ENROLMENT,
        attr::SESSION,
        &discard_tlv(HANDLE),
        DISCARD_PLAINTEXT_LEN,
    );
    assert_wrapped(
        &sent[2],
        cmd::ARM_CAPTURE,
        attr::CAPTURE,
        &common::capture_tlv(HANDLE),
        80,
    );
    assert_wrapped(
        &sent[3],
        cmd::UPDATE_ENROLMENT,
        attr::SESSION,
        &update_tlv(HANDLE, &SAMPLE_HASH),
        UPDATE_PLAINTEXT_LEN,
    );
    assert_wrapped(
        &sent[6],
        cmd::COMMIT_ENROLMENT,
        attr::SESSION,
        &commit_tlv(HANDLE, &ENROLMENT_ID),
        COMMIT_PLAINTEXT_LEN,
    );

    assert_eq!(
        progress
            .iter()
            .map(|seen| seen.accepted_samples)
            .collect::<Vec<_>>(),
        vec![0, 0, 0, 0, 1, 1, 1, 2, 2, 2],
        "progress is observable after each accepted update"
    );
}

fn assert_wrapped(frame: &[u8], command: u16, attribute: u8, tlv: &[u8], plaintext_len: usize) {
    assert_eq!(&frame[8..10], &command.to_le_bytes(), "command");
    assert_eq!(frame[10], attribute, "attribute");
    assert_eq!(frame[11], 0x02, "wrapped encoding");
    assert_eq!(le32(frame, 16), HANDLE, "header handle");
    assert_eq!(le32(frame, 40), tlv.len() as u32, "declared TLV length");
    assert_eq!(
        frame.len(),
        frame::HEADER_LEN + (plaintext_len / 16 + 1) * 16,
        "ciphertext length"
    );
}

#[test]
fn forcing_the_sample_hash_commits_it_even_when_an_enrolment_id_arrives() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let expected_commit = session
        .wrap(
            cmd::COMMIT_ENROLMENT,
            attr::SESSION,
            &commit_tlv(HANDLE, &SAMPLE_HASH),
            COMMIT_PLAINTEXT_LEN,
            &enrol_iv(&base_iv(), 5),
            6,
        )
        .expect("commit frame");

    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_accepted_update(&mut transport, &session);
    push_arm(&mut transport, &session);
    push_completion(&mut transport, &session);
    push_commit_reply(&mut transport, &session, 0);

    let mut enrol = Enrol::new(session, base_iv()).with_commit_sample_hash();
    let (outcome, _) = drive_with_progress(&mut enrol, &mut transport);
    let template = outcome.expect("the enrolment completes");
    transport.assert_exhausted();

    assert_eq!(
        template.template_id, SAMPLE_HASH,
        "the flag overrides the enrolment id the sensor sent"
    );
    assert_eq!(template.source, TemplateSource::ForcedSampleHash);
    assert_eq!(
        transport.sent().last(),
        Some(&expected_commit),
        "the commit names the last sample hash"
    );
}

#[test]
fn the_tlv_builders_match_the_documented_wire_offsets() {
    let discard = discard_tlv(HANDLE);
    assert_eq!(discard.len(), DISCARD_TLV_LEN);
    assert_eq!(&discard[0..4], &0u32.to_le_bytes());
    assert_eq!(&discard[4..8], &4u32.to_le_bytes());
    assert_eq!(&discard[8..12], &HANDLE.to_le_bytes());

    assert_eq!(start_tlv(), [0u8; START_TLV_LEN]);

    let update = update_tlv(HANDLE, &SAMPLE_HASH);
    assert_eq!(update.len(), UPDATE_TLV_LEN);
    assert_eq!(&update[0..12], &discard);
    assert_eq!(&update[12..16], &0u32.to_le_bytes(), "tag 0");
    assert_eq!(&update[16..20], &20u32.to_le_bytes(), "sample hash length");
    assert_eq!(&update[20..40], &SAMPLE_HASH, "sample hash");
    assert_eq!(&update[40..44], &2u32.to_le_bytes(), "tag 2");
    assert_eq!(&update[44..48], &0u32.to_le_bytes(), "value 0");

    let commit = commit_tlv(HANDLE, &ENROLMENT_ID);
    assert_eq!(commit.len(), COMMIT_TLV_LEN);
    assert_eq!(&commit[0..12], &discard);
    assert_eq!(&commit[12..16], &0u32.to_le_bytes(), "tag 0");
    assert_eq!(&commit[16..20], &20u32.to_le_bytes(), "template id length");
    assert_eq!(&commit[20..40], &ENROLMENT_ID, "template id");
    assert_eq!(&commit[40..44], &2u32.to_le_bytes());
    assert_eq!(&commit[44..48], &0u32.to_le_bytes());
    assert_eq!(&commit[48..52], &2u32.to_le_bytes());
    assert_eq!(&commit[52..56], &0u32.to_le_bytes());
    assert_eq!(&commit[56..60], &3u32.to_le_bytes());
    assert_eq!(&commit[60..64], &0u32.to_le_bytes());
}

#[test]
fn the_same_base_iv_derives_a_different_iv_per_wrapped_frame() {
    let first = enrol_iv(&base_iv(), 0);
    let second = enrol_iv(&base_iv(), 1);
    assert_ne!(first, second);
    assert_ne!(first, base_iv());
    assert_eq!(
        first,
        enrol_iv(&base_iv(), 0),
        "the derivation is deterministic"
    );
    assert_eq!(MAX_ACCEPTED_SAMPLES, 12);
    assert_eq!(MAX_CAPTURE_ATTEMPTS, 30);
}

#[test]
fn a_sample_rejected_for_quality_is_requested_again_and_not_counted() {
    for rescan in [status::RESCAN_A, status::RESCAN_B] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard_reply(&mut transport, &session);
        push_start_reply(&mut transport);

        // An accepted sample, a rejected one, then a completion.
        push_arm(&mut transport, &session);
        push_accepted_update(&mut transport, &session);
        push_arm(&mut transport, &session);
        push_update(
            &mut transport,
            &session,
            rescan,
            &twenty_byte_tlv(&SAMPLE_HASH),
        );
        push_arm(&mut transport, &session);
        push_completion(&mut transport, &session);
        push_commit_reply(&mut transport, &session, 0);

        let (outcome, progress) = enrol_and_drive(&mut transport, session);
        let template = outcome.expect("the rescan is retried, not fatal");
        transport.assert_exhausted();

        assert_eq!(template.accepted_samples, 2);
        assert_eq!(template.source, TemplateSource::EnrolmentId);
        assert_eq!(template.template_id, ENROLMENT_ID);
        let last = progress.last().expect("a final progress");
        assert_eq!(last.accepted_samples, 2);
        assert_eq!(last.rejected_samples, 1);
        assert_eq!(last.capture_attempts, 3, "the rescan consumed an arm");

        let commands = sent_commands(&transport);
        assert_eq!(
            commands,
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
                cmd::ARM_CAPTURE,
                cmd::UPDATE_ENROLMENT,
                cmd::COMMIT_ENROLMENT,
            ],
            "the rejected sample is not counted and is requested again"
        );
    }
}

#[test]
fn twelve_accepted_samples_without_completion_commit_the_last_sample_hash() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let expected_commit = session
        .wrap(
            cmd::COMMIT_ENROLMENT,
            attr::SESSION,
            &commit_tlv(HANDLE, &SAMPLE_HASH),
            COMMIT_PLAINTEXT_LEN,
            &enrol_iv(&base_iv(), 2 * MAX_ACCEPTED_SAMPLES as u32 + 1),
            2 * MAX_ACCEPTED_SAMPLES as u32 + 2,
        )
        .expect("commit frame");

    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    for _ in 0..MAX_ACCEPTED_SAMPLES {
        push_arm(&mut transport, &session);
        push_accepted_update(&mut transport, &session);
    }
    push_commit_reply(&mut transport, &session, 0);

    let (outcome, progress) = enrol_and_drive(&mut transport, session);
    let template = outcome.expect("twelve accepted samples are enough");
    transport.assert_exhausted();

    assert_eq!(template.accepted_samples, MAX_ACCEPTED_SAMPLES);
    assert_eq!(template.source, TemplateSource::SampleHash);
    assert_eq!(template.template_id, SAMPLE_HASH);
    assert_eq!(
        template.session.next_sequence(),
        2 * MAX_ACCEPTED_SAMPLES as u32 + 3,
        "twelve arms, twelve updates, the discard and the commit each advanced once"
    );

    let commands = sent_commands(&transport);
    assert_eq!(commands[3], cmd::DISCARD_ENROLMENT);
    assert_eq!(commands[4], cmd::START_ENROLMENT);
    for sample in 0..MAX_ACCEPTED_SAMPLES {
        assert_eq!(
            commands[5 + sample * 2],
            cmd::ARM_CAPTURE,
            "sample {sample}"
        );
        assert_eq!(
            commands[6 + sample * 2],
            cmd::UPDATE_ENROLMENT,
            "sample {sample}"
        );
    }
    assert_eq!(
        commands[5 + MAX_ACCEPTED_SAMPLES * 2],
        cmd::COMMIT_ENROLMENT
    );
    assert_eq!(
        transport.sent().last().expect("a commit"),
        &expected_commit,
        "the commit names the last sample hash"
    );

    let accepted: Vec<usize> = progress.iter().map(|seen| seen.accepted_samples).collect();
    for count in 1..=MAX_ACCEPTED_SAMPLES {
        assert!(
            accepted.contains(&count),
            "progress never reached {count}: {accepted:?}"
        );
    }
}

#[test]
fn the_sensor_stopping_early_without_a_completion_fails_and_commits_nothing() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    for _ in 0..5 {
        push_arm(&mut transport, &session);
        push_accepted_update(&mut transport, &session);
    }
    push_arm(&mut transport, &session);
    push_update(
        &mut transport,
        &session,
        status::ENROLMENT_FULL,
        &twenty_byte_tlv(&SAMPLE_HASH),
    );
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    assert_eq!(
        outcome,
        Err(EnrolError::Incomplete {
            accepted: 5,
            required: MAX_ACCEPTED_SAMPLES,
        })
    );
    let error = outcome.expect_err("the run fails");
    assert!(!error.may_have_stored_template());
    assert!(error.pending_enrolment_remains());
    assert!(
        error.to_string().contains("no template was stored"),
        "{error}"
    );
    assert!(
        error.to_string().contains("pending enrolment may remain"),
        "{error}"
    );
    assert_teardown(&transport);
    assert!(
        !sent_commands(&transport).contains(&cmd::COMMIT_ENROLMENT),
        "nothing is committed"
    );
}

#[test]
fn an_update_rejected_with_another_status_is_distinct_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_update(
        &mut transport,
        &session,
        0x0c,
        &twenty_byte_tlv(&SAMPLE_HASH),
    );
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    assert_eq!(
        outcome,
        Err(EnrolError::UpdateRejected {
            status: 0x0c,
            accepted: 0,
        })
    );
    assert_teardown(&transport);
    assert!(!sent_commands(&transport).contains(&cmd::COMMIT_ENROLMENT));
}

#[test]
fn a_failed_commit_is_reported_and_the_next_enrolment_starts_with_a_discard() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_completion(&mut transport, &session);
    push_commit_reply(&mut transport, &session, 0x0c);
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    let error = outcome.expect_err("the commit was rejected");
    assert_eq!(error, EnrolError::CommitRejected { status: 0x0c });
    assert!(
        error.may_have_stored_template(),
        "a commit was attempted, so a template may exist"
    );
    assert!(error.pending_enrolment_remains());
    let text = error.to_string();
    assert!(text.contains("may exist"), "{text}");
    assert!(text.contains("pending enrolment may remain"), "{text}");
    assert_teardown(&transport);

    // A fresh run always discards first, so the rejected attempt is cleared before `0x8A`.
    let mut next_transport = ScriptedTransport::default();
    let next_session = opened_session(&mut next_transport);
    let expected_discard = next_session
        .wrap(
            cmd::DISCARD_ENROLMENT,
            attr::SESSION,
            &discard_tlv(HANDLE),
            DISCARD_PLAINTEXT_LEN,
            &enrol_iv(&base_iv(), 0),
            1,
        )
        .expect("discard frame");
    let mut next = Enrol::new(next_session, base_iv());
    assert_eq!(next.start(), Action::Send(expected_discard));
}

#[test]
fn a_finger_that_never_arrives_fails_cleanly_and_reports_the_pending_enrolment() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: capture_reply(&session, 0, &sample_hash_plaintext()),
    });
    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    let error = outcome.expect_err("the finger never arrived");
    assert_eq!(
        error,
        EnrolError::Capture(cv3_core::CaptureError::FingerTimeout)
    );
    assert!(!error.may_have_stored_template());
    let text = error.to_string();
    assert!(text.contains("no template was stored"), "{text}");
    assert!(text.contains("pending enrolment may remain"), "{text}");
    assert!(text.contains("next discard"), "{text}");
    assert_teardown(&transport);
}

fn transport_failure_at_discard() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();
    assert_eq!(
        outcome,
        Err(EnrolError::Transport {
            stage: EnrolStage::Discard,
            error: TransportError::Disconnected,
        })
    );
    assert!(!outcome.expect_err("a failure").may_have_stored_template());
    assert_teardown(&transport);
}

#[test]
fn a_transport_failure_at_the_discard_tears_down() {
    transport_failure_at_discard();
}

#[test]
fn a_transport_failure_at_the_start_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();
    assert_eq!(
        outcome,
        Err(EnrolError::Transport {
            stage: EnrolStage::Start,
            error: TransportError::Disconnected,
        })
    );
    assert_teardown(&transport);
}

#[test]
fn a_transport_failure_at_the_capture_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    transport.push(ScriptedOutcome::Transport(TransportError::Timeout));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();
    assert_eq!(
        outcome,
        Err(EnrolError::Transport {
            stage: EnrolStage::Capture,
            error: TransportError::Timeout,
        })
    );
    assert_teardown(&transport);
}

#[test]
fn a_transport_failure_at_the_update_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    transport.push(ScriptedOutcome::Transport(TransportError::Stall));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();
    assert_eq!(
        outcome,
        Err(EnrolError::Transport {
            stage: EnrolStage::Update,
            error: TransportError::Stall,
        })
    );
    assert_teardown(&transport);
}

#[test]
fn a_transport_failure_at_the_commit_tears_down_and_says_a_template_may_exist() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_completion(&mut transport, &session);
    transport.push(ScriptedOutcome::Transport(TransportError::Disconnected));
    push_teardown(&mut transport);

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    let error = outcome.expect_err("the commit transfer failed");
    assert_eq!(
        error,
        EnrolError::Transport {
            stage: EnrolStage::Commit,
            error: TransportError::Disconnected,
        }
    );
    assert!(error.may_have_stored_template());
    assert!(error.to_string().contains("may exist"), "{error}");
    assert_teardown(&transport);
}

#[test]
fn cancellation_at_the_finger_wait_and_at_the_update_tears_down() {
    for (cancel_at_finger, expected_stage) in
        [(true, EnrolStage::Capture), (false, EnrolStage::Update)]
    {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard_reply(&mut transport, &session);
        push_start_reply(&mut transport);
        if cancel_at_finger {
            transport.push(ScriptedOutcome::Reply {
                status: 0,
                body: capture_reply(&session, 0, &sample_hash_plaintext()),
            });
            transport.push(ScriptedOutcome::Cancelled);
        } else {
            push_arm(&mut transport, &session);
            transport.push(ScriptedOutcome::Cancelled);
        }
        push_teardown(&mut transport);

        let (outcome, _) = enrol_and_drive(&mut transport, session);
        transport.assert_exhausted();
        assert_eq!(
            outcome,
            Err(EnrolError::Cancelled {
                stage: expected_stage
            })
        );
        assert_teardown(&transport);
    }
}

#[test]
fn a_sensor_that_keeps_rejecting_samples_hits_the_attempt_cap() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    for _ in 0..MAX_CAPTURE_ATTEMPTS {
        push_arm(&mut transport, &session);
        push_update(
            &mut transport,
            &session,
            status::RESCAN_A,
            &twenty_byte_tlv(&SAMPLE_HASH),
        );
    }
    push_teardown(&mut transport);

    let (outcome, progress) = enrol_and_drive(&mut transport, session);
    transport.assert_exhausted();

    let error = outcome.expect_err("the cap ends the run");
    assert_eq!(
        error,
        EnrolError::AttemptLimit {
            attempts: MAX_CAPTURE_ATTEMPTS,
            accepted: 0,
        }
    );
    assert!(!error.may_have_stored_template());
    assert_eq!(
        progress.last().expect("a final progress").capture_attempts,
        MAX_CAPTURE_ATTEMPTS
    );
    assert_teardown(&transport);
    let commands = sent_commands(&transport);
    assert!(
        !commands.contains(&cmd::COMMIT_ENROLMENT),
        "a run that never accepted a sample commits nothing"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| **command == cmd::ARM_CAPTURE)
            .count(),
        MAX_CAPTURE_ATTEMPTS
    );
}

#[test]
fn a_malformed_or_oversized_update_reply_is_distinct_and_tears_down() {
    for (body, wanted) in [
        (
            vec![0u8; 10],
            UnwrapError::Frame(FrameError::Short {
                got: 10,
                need: frame::HEADER_LEN,
            }),
        ),
        (
            frame::build_wrapped(
                cmd::UPDATE_ENROLMENT,
                attr::SESSION,
                HANDLE,
                &fixed_iv(),
                0,
                &vec![0u8; 4_112],
            ),
            UnwrapError::CiphertextTooLarge {
                got: 4_112,
                max: cv3_core::session::MAX_CIPHERTEXT_LEN,
            },
        ),
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard_reply(&mut transport, &session);
        push_start_reply(&mut transport);
        push_arm(&mut transport, &session);
        transport.push(ScriptedOutcome::Reply {
            status: status::SAMPLE_ACCEPTED,
            body,
        });
        push_teardown(&mut transport);

        let (outcome, _) = enrol_and_drive(&mut transport, session);
        transport.assert_exhausted();
        assert_eq!(
            outcome,
            Err(EnrolError::MalformedReply {
                stage: EnrolStage::Update,
                error: wanted,
            })
        );
        assert_teardown(&transport);
    }
}

#[test]
fn a_bodyless_or_malformed_commit_reply_says_a_template_may_exist() {
    for outcome in [
        ScriptedOutcome::ReplyWithoutBody,
        ScriptedOutcome::Reply {
            status: 0,
            body: vec![0u8; 10],
        },
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        push_discard_reply(&mut transport, &session);
        push_start_reply(&mut transport);
        push_arm(&mut transport, &session);
        push_completion(&mut transport, &session);
        transport.push(outcome);
        push_teardown(&mut transport);

        let (result, _) = enrol_and_drive(&mut transport, session);
        transport.assert_exhausted();

        let error = result.expect_err("the commit reply is unusable");
        assert!(error.may_have_stored_template());
        assert!(error.pending_enrolment_remains());
        assert!(error.to_string().contains("may exist"), "{error}");
        assert_teardown(&transport);
    }
}

#[test]
fn the_commit_reply_plaintext_is_kept_for_the_probe() {
    // The vendor's commit out-list is `(3, blob)(0,4,u32)`: `cvhSaveReturnValues` confirms the
    // reply carries a type-3 blob and the type-0 u32 that identify later names.
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&8u32.to_le_bytes());
    plaintext.extend_from_slice(&[0xaa; 8]);
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&4u32.to_le_bytes());
    plaintext.extend_from_slice(&0x1122_3344u32.to_le_bytes());

    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_completion(&mut transport, &session);
    let body = wrapped_reply(
        &session,
        cmd::COMMIT_ENROLMENT,
        attr::SESSION,
        0,
        &plaintext,
    );
    let reply_len = body.len();
    transport.push(ScriptedOutcome::Reply { status: 0, body });

    let (outcome, _) = enrol_and_drive(&mut transport, session);
    let template = outcome.expect("the enrolment completes");

    assert_eq!(template.commit_plaintext, plaintext);
    assert_eq!(template.commit_reply_len, reply_len);
    assert_eq!(
        template.commit_plaintext.len(),
        28,
        "the type-3 blob plus the type-0 u32"
    );
}

#[test]
fn a_finished_enrolment_is_inert_and_does_not_panic() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    push_discard_reply(&mut transport, &session);
    push_start_reply(&mut transport);
    push_arm(&mut transport, &session);
    push_completion(&mut transport, &session);
    push_commit_reply(&mut transport, &session, 0);

    let mut enrol = Enrol::new(session, base_iv());
    let (outcome, _) = drive_with_progress(&mut enrol, &mut transport);
    let template = outcome.expect("the enrolment completes");
    assert_eq!(template.source, TemplateSource::EnrolmentId);

    assert_eq!(
        enrol.step(Event::Finger),
        Action::Finish(Err(EnrolError::AlreadyFinished))
    );
    assert_eq!(
        enrol.start(),
        Action::Finish(Err(EnrolError::AlreadyFinished))
    );
}

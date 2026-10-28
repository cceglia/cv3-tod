//! The `0x2F` inventory query and the pure TLV scan its reply is dumped with.
//!
//! Every expected frame is built from constants written out here, taken from the reference tool
//! (`tmp/cv3-review/tools/cvchan.c`) and the audit notes, never from the module under test.

mod common;

use common::{HANDLE, fixed_iv, opened_session};
use cv3_core::crypto;
use cv3_core::frame;
use cv3_core::inventory::{
    INVENTORY_PLAINTEXT_LEN, INVENTORY_TLV_LEN, Inventory, InventoryError, TLV_HEADER_LEN,
    inventory_tlv, scan_tlv,
};
use cv3_core::proto::{attr, cmd};
use cv3_core::session::{Session, UnwrapError};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::{Action, Event, Operation, Transport, TransportError};

/// The reference's 56-byte `0x2F` parameter block, byte for byte from `cvchan.c`.
///
/// `(0,4,handle) (0,4,0x48) (0,4,0x53e2) (0,4,0) (2,0)`. The handle at offset 8 is patched by
/// [`reference_inventory_tlv`].
const REFERENCE_TLV: [u8; 56] = [
    0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 4, 0, 0, 0, 0x48, 0, 0, 0, //
    0, 0, 0, 0, 4, 0, 0, 0, 0xe2, 0x53, 0, 0, //
    0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
    2, 0, 0, 0, 0, 0, 0, 0,
];

fn reference_inventory_tlv(handle: u32) -> [u8; 56] {
    let mut tlv = REFERENCE_TLV;
    tlv[8..12].copy_from_slice(&handle.to_le_bytes());
    tlv
}

/// The IV the operation is built with.
fn inventory_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x60 + index as u8;
    }
    iv
}

/// The exact frame the operation must send: the reference TLV, 88-byte plaintext, next sequence.
fn expected_inventory_frame(session: &Session) -> Vec<u8> {
    session
        .wrap(
            cmd::INVENTORY,
            attr::INVENTORY,
            &reference_inventory_tlv(session.handle),
            88,
            &inventory_iv(),
            session.next_sequence(),
        )
        .expect("the inventory constants build a frame")
}

/// A synthetic wrapped inventory reply with `status` and `plaintext` inside the ciphertext.
fn inventory_reply(session: &Session, status: u32, plaintext: &[u8]) -> Vec<u8> {
    let iv = fixed_iv();
    let ciphertext = crypto::encrypt_cbc(session.key().as_bytes(), &iv, plaintext);
    let mut body = frame::build_wrapped(
        cmd::INVENTORY,
        attr::INVENTORY,
        session.handle,
        &iv,
        plaintext.len() as u32,
        &ciphertext,
    );
    body[20..24].copy_from_slice(&status.to_le_bytes());
    body[11] = cv3_core::proto::Encoding::WrappedReply as u8;
    body
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
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

#[test]
fn the_query_is_the_reference_frame_at_the_sessions_next_sequence() {
    assert_eq!(INVENTORY_TLV_LEN, REFERENCE_TLV.len());
    assert_eq!(INVENTORY_PLAINTEXT_LEN, 88);
    assert_eq!(inventory_tlv(HANDLE), reference_inventory_tlv(HANDLE));

    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    assert_eq!(
        session.next_sequence(),
        1,
        "the wrapped open consumed sequence zero"
    );
    let expected = expected_inventory_frame(&session);
    let body = inventory_reply(&session, 0, &[0u8; 88]);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: body.clone(),
    });
    let mut inventory = Inventory::new(session, inventory_iv());
    let reply = run(&mut inventory, &mut transport).expect("the scripted sensor answers");
    transport.assert_exhausted();

    let sent = transport.sent();
    assert_eq!(
        sent.last(),
        Some(&expected),
        "the query is the 56-byte block at sequence 1"
    );

    let frame = sent.last().expect("one command");
    assert_eq!(
        frame.len(),
        140,
        "44-byte header plus six ciphertext blocks"
    );
    assert_eq!(&frame[8..10], &cmd::INVENTORY.to_le_bytes());
    assert_eq!(frame[10], attr::INVENTORY);
    assert_eq!(frame[11], 0x02, "a host command is wrapped");
    assert_eq!(le32(frame, 16), HANDLE);
    assert_eq!(le32(frame, frame::PARAM_LEN_OFFSET), 56);
    assert_eq!(reply.reply_len, body.len());
}

#[test]
fn the_two_lengths_and_the_whole_plaintext_are_reported() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let plaintext = scan_plaintext();
    let body = inventory_reply(&session, 0, &plaintext);

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: body.clone(),
    });
    let mut inventory = Inventory::new(session, inventory_iv());
    let reply = run(&mut inventory, &mut transport).expect("the dump is returned");

    assert_eq!(
        reply.reply_len,
        body.len(),
        "the raw reply, header included"
    );
    assert_eq!(reply.plaintext, plaintext);
    assert_eq!(reply.plaintext.len(), 88);
}

/// A realistic 88-byte inventory reply plaintext: three entries filling the reply exactly.
fn scan_plaintext() -> Vec<u8> {
    let mut plaintext = vec![0u8; 88];
    // (0, 4, 0x11223344) at 0
    plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
    plaintext[8..12].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    // (1, 20, id) at 12
    plaintext[12..16].copy_from_slice(&1u32.to_le_bytes());
    plaintext[16..20].copy_from_slice(&20u32.to_le_bytes());
    plaintext[20..40].copy_from_slice(&[0xa5u8; 20]);
    // (3, 40, value) at 40, filling the reply
    plaintext[40..44].copy_from_slice(&3u32.to_le_bytes());
    plaintext[44..48].copy_from_slice(&40u32.to_le_bytes());
    for (index, byte) in plaintext[48..88].iter_mut().enumerate() {
        *byte = index as u8;
    }
    plaintext
}

#[test]
fn a_bodyless_reply_is_its_own_error_and_tears_down() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::ReplyWithoutBody);

    let mut inventory = Inventory::new(session, inventory_iv());
    let error = run(&mut inventory, &mut transport).expect_err("no body means no dump");

    assert_eq!(error, InventoryError::MissingReply);
    assert_teardown(&transport);
}

#[test]
fn a_plaintext_too_short_for_one_tlv_header_is_its_own_error() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let body = inventory_reply(&session, 0, &[1, 2, 3, 4]);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: body.clone(),
    });

    let mut inventory = Inventory::new(session, inventory_iv());
    let error = run(&mut inventory, &mut transport).expect_err("four bytes are not a TLV");

    assert_eq!(
        error,
        InventoryError::ShortReply {
            plaintext_len: 4,
            reply_len: body.len(),
        }
    );
    assert_teardown(&transport);
}

#[test]
fn a_sensor_status_keeps_the_reply_length_and_plaintext_for_the_message() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    let plaintext = [0u8; 32];
    let body = inventory_reply(&session, 0x0e, &plaintext);
    transport.push(ScriptedOutcome::Reply {
        status: 0x0e,
        body: body.clone(),
    });

    let mut inventory = Inventory::new(session, inventory_iv());
    let error = run(&mut inventory, &mut transport).expect_err("0x0e is not a dump");

    assert_eq!(
        error,
        InventoryError::SensorStatus {
            status: 0x0e,
            reply_len: body.len(),
            plaintext: Some(plaintext.to_vec()),
        }
    );
    let message = error.to_string();
    assert!(message.contains("0x0e"), "{message}");
    assert!(message.contains("32 bytes"), "{message}");
    assert_teardown(&transport);
}

#[test]
fn a_sequence_rejection_is_its_own_error() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: cv3_core::proto::status::BAD_SEQUENCE,
        body: inventory_reply(&session, cv3_core::proto::status::BAD_SEQUENCE, &[0u8; 88]),
    });

    let mut inventory = Inventory::new(session, inventory_iv());
    let error = run(&mut inventory, &mut transport).expect_err("0x0f is a refusal");

    assert_eq!(error, InventoryError::WrongSequence);
    assert_teardown(&transport);
}

#[test]
fn an_undecryptable_body_is_a_malformed_reply_and_tears_down() {
    for (body, header_only) in [
        (
            frame::build_wrapped(cmd::INVENTORY, attr::INVENTORY, HANDLE, &fixed_iv(), 0, &[]),
            true,
        ),
        (vec![0u8; 10], false),
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        transport.push(ScriptedOutcome::Reply {
            status: 0,
            body: body.clone(),
        });

        let mut inventory = Inventory::new(session, inventory_iv());
        let error = run(&mut inventory, &mut transport).expect_err("the body is not wrapped");

        match error {
            InventoryError::MalformedReply(UnwrapError::EmptyCiphertext) => {
                assert!(header_only, "a header-only wrapped frame");
            }
            InventoryError::MalformedReply(UnwrapError::Frame(_)) => {
                assert!(!header_only, "a body too short for a header");
            }
            other => panic!("expected a malformed reply, got {other:?}"),
        }
        assert_teardown(&transport);
    }
}

#[test]
fn a_transport_failure_and_a_cancellation_tear_down_and_keep_their_meaning() {
    for (event, expected) in [
        (
            Event::Transport(TransportError::Timeout),
            InventoryError::Transport(TransportError::Timeout),
        ),
        (Event::Cancelled, InventoryError::Cancelled),
    ] {
        let mut transport = ScriptedTransport::default();
        let session = opened_session(&mut transport);
        transport.push(ScriptedOutcome::from(event));

        let mut inventory = Inventory::new(session, inventory_iv());
        let error = run(&mut inventory, &mut transport).expect_err("the transfer failed");

        assert_eq!(error, expected);
        assert_teardown(&transport);
    }
}

#[test]
fn a_finished_inventory_is_inert_and_does_not_panic() {
    let mut transport = ScriptedTransport::default();
    let session = opened_session(&mut transport);
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: inventory_reply(&session, 0, &[0u8; 88]),
    });

    let mut inventory = Inventory::new(session, inventory_iv());
    let Action::Send(frame) = inventory.start() else {
        panic!("the query starts with a send");
    };
    assert!(matches!(
        inventory.step(transport.command(&frame)),
        Action::Finish(Ok(_))
    ));

    match inventory.step(Event::Finger) {
        Action::Finish(Err(error)) => assert_eq!(error, InventoryError::AlreadyFinished),
        other => panic!("expected the inert result, got {other:?}"),
    }
}

#[test]
fn the_tlv_scan_reads_the_reference_query_block() {
    let reference = reference_inventory_tlv(HANDLE);
    let scan = scan_tlv(&reference);

    assert_eq!(scan.entries.len(), 5);
    assert_eq!(scan.trailing, 0);
    assert!(!scan.truncated);

    let expected: [(usize, u32, u32); 3] = [(0, 0, HANDLE), (12, 0, 0x48), (24, 0, 0x53e2)];
    for (index, (offset, tag, value)) in expected.iter().enumerate() {
        let entry = &scan.entries[index];
        assert_eq!(entry.offset, *offset);
        assert_eq!(entry.tag, *tag);
        assert_eq!(entry.declared_len, 4);
        assert_eq!(le32(entry.value, 0), *value);
    }
    let zero = &scan.entries[3];
    assert_eq!(zero.offset, 36);
    assert_eq!(zero.tag, 0);
    assert_eq!(zero.declared_len, 4);
    assert_eq!(le32(zero.value, 0), 0);
    let last = &scan.entries[4];
    assert_eq!(last.offset, 48);
    assert_eq!(last.tag, 2);
    assert_eq!(last.declared_len, 0);
    assert!(last.value.is_empty());
}

#[test]
fn the_tlv_scan_reads_a_reply_and_rounds_each_entry_to_a_four_byte_boundary() {
    let plaintext = scan_plaintext();
    let scan = scan_tlv(&plaintext);

    assert_eq!(scan.entries.len(), 3);
    assert_eq!(scan.trailing, 0);
    assert!(!scan.truncated);

    assert_eq!(scan.entries[0].offset, 0);
    assert_eq!(scan.entries[0].tag, 0);
    assert_eq!(scan.entries[0].value, &0x1122_3344u32.to_le_bytes());
    assert_eq!(scan.entries[1].offset, 12);
    assert_eq!(scan.entries[1].tag, 1);
    assert_eq!(scan.entries[1].value, &[0xa5u8; 20]);
    assert_eq!(scan.entries[2].offset, 40);
    assert_eq!(scan.entries[2].tag, 3);
    assert_eq!(scan.entries[2].declared_len, 40);
    assert_eq!(scan.entries[2].value.len(), 40);

    // A five-byte value is padded to eight before the next header.
    let mut padded = vec![0u8; 28];
    padded[4..8].copy_from_slice(&5u32.to_le_bytes());
    padded[8..13].copy_from_slice(&[1, 2, 3, 4, 5]);
    padded[16..20].copy_from_slice(&1u32.to_le_bytes());
    padded[20..24].copy_from_slice(&4u32.to_le_bytes());
    padded[24..28].copy_from_slice(&9u32.to_le_bytes());
    let padded = scan_tlv(&padded);
    assert_eq!(padded.entries[0].value, &[1, 2, 3, 4, 5]);
    assert_eq!(padded.entries[1].offset, 16);
    assert_eq!(padded.entries[1].tag, 1);
}

#[test]
fn the_tlv_scan_never_panics_on_empty_short_or_lying_plaintexts() {
    for (plaintext, entries, trailing) in [
        (&[][..], 0, 0),
        (&[0u8; 7][..], 0, 7),
        (&[0u8; 88][..], 11, 0),
    ] {
        let scan = scan_tlv(plaintext);
        assert_eq!(scan.entries.len(), entries, "{} bytes", plaintext.len());
        assert_eq!(scan.trailing, trailing, "{} bytes", plaintext.len());
        assert!(!scan.truncated);
    }

    // A declared value longer than the buffer is reported, not sliced past the end.
    let mut lying = vec![0u8; 12];
    lying[4..8].copy_from_slice(&40u32.to_le_bytes());
    lying[8..12].copy_from_slice(&[7, 8, 9, 10]);
    let scan = scan_tlv(&lying);
    assert_eq!(scan.entries.len(), 1);
    assert!(scan.truncated);
    assert_eq!(scan.entries[0].declared_len, 40);
    assert_eq!(scan.entries[0].value, &[7, 8, 9, 10]);
    assert_eq!(TLV_HEADER_LEN, 8);
}

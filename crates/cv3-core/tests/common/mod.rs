//! Synthetic fixtures shared by the core's integration tests.
//!
//! Every value comes from the protocol description or a public standard; nothing here was captured
//! from a sensor.

#![allow(dead_code)]

use cv3_core::crypto::HostKey;
use cv3_core::frame;
use cv3_core::proto::{attr, cmd};
use cv3_core::session::{OpenSession, Session};
use cv3_core::transport::{ScriptedOutcome, ScriptedTransport, run};
use cv3_core::{Handshake, crypto};

pub const HANDLE: u32 = 0x1122_3344;

pub fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
            let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
            (high << 4) | low
        })
        .collect();
    assert_eq!(bytes.len(), N);
    bytes.try_into().expect("length checked")
}

/// RFC 5903, section 8.1: the initiator's scalar.
pub fn host_secret() -> [u8; 32] {
    unhex("c88f01f510d9ac3f70a292daa2316de5 44e9aab8afe84049c62a9c57862d1433")
}

/// RFC 5903, section 8.1: the initiator's public key (`g^i`).
pub fn host_public() -> [u8; 64] {
    unhex(
        "dad0b65394221cf9b051e1feca5787d0 98dfe637fc90b9ef945d0c3772581180 \
         5271a0461cdb8252d61f1c456fa3e59a b1f45b33accf5f58389e0577b8990bb3",
    )
}

/// RFC 5903, section 8.1: the responder's public key, used as the device's.
pub fn device_public() -> [u8; 64] {
    unhex(
        "d12dfb5289c8d4f81208b70270398c34 2296970a0bccb74c736fc7554494bf63 \
         56fbf3ca366cc23e8157854c13c58d6a ac23f046ada30f8353e74f33039872ab",
    )
}

pub fn device_nonce() -> [u8; 20] {
    unhex("000102030405060708090a0b0c0d0e0f10111213")
}

pub fn host_nonce() -> [u8; 20] {
    unhex("202122232425262728292a2b2c2d2e2f30313233")
}

pub fn client_nonce() -> [u8; 20] {
    unhex("404142434445464748494a4b4c4d4e4f50515253")
}

pub fn host_key() -> HostKey {
    HostKey::from_bytes(&host_secret()).expect("the RFC scalar is valid")
}

pub fn challenge_reply(status: u32) -> Vec<u8> {
    let mut param = [0u8; 148];
    param[..64].copy_from_slice(&device_public());
    param[64..128].fill(0xcc);
    param[128..].copy_from_slice(&device_nonce());
    frame::build_plain_reply(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, status, &param)
}

pub fn response_reply(status: u32) -> Vec<u8> {
    frame::build_plain_reply(
        cmd::CHALLENGE_RESPONSE,
        attr::CHALLENGE_RESPONSE,
        HANDLE,
        status,
        &[],
    )
}

pub fn open_reply(status: u32) -> Vec<u8> {
    frame::build_plain_reply(cmd::OPEN_SESSION, attr::SESSION, HANDLE, status, &[])
}

pub fn challenge_frame() -> Vec<u8> {
    let mut param = [0u8; 24];
    param[..20].copy_from_slice(&client_nonce());
    param[20..].copy_from_slice(&1u32.to_le_bytes());
    frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &param)
}

pub fn response_frame() -> Vec<u8> {
    let mut param = [0u8; 84];
    param[..20].copy_from_slice(&host_nonce());
    param[20..].copy_from_slice(&host_public());
    frame::build_plain(
        cmd::CHALLENGE_RESPONSE,
        attr::CHALLENGE_RESPONSE,
        HANDLE,
        &param,
    )
}

pub fn fixed_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x10 + index as u8;
    }
    iv
}

/// The sample hash a synthetic arm reply carries.
pub const SAMPLE_HASH: [u8; 20] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23,
];

/// The documented 36-byte `0x66` parameter block, built independently of the implementation.
pub fn capture_tlv(handle: u32) -> [u8; 36] {
    let mut tlv = [0u8; 36];
    for length_at in [4usize, 16, 28] {
        tlv[length_at..length_at + 4].copy_from_slice(&4u32.to_le_bytes());
    }
    tlv[8..12].copy_from_slice(&handle.to_le_bytes());
    tlv[20..24].copy_from_slice(&1u32.to_le_bytes());
    tlv[32..36].copy_from_slice(&0x23u32.to_le_bytes());
    tlv
}

/// The exact wrapped `0x66` frame a capture must send for `session`.
pub fn arm_frame(session: &Session, iv: &[u8; 16]) -> Vec<u8> {
    arm_frame_at(session, iv, session.next_sequence())
}

/// The exact wrapped `0x66` frame for `session` at an explicit wrap sequence.
pub fn arm_frame_at(session: &Session, iv: &[u8; 16], sequence: u32) -> Vec<u8> {
    session
        .wrap(
            cmd::ARM_CAPTURE,
            attr::CAPTURE,
            &capture_tlv(session.handle),
            80,
            iv,
            sequence,
        )
        .expect("the capture constants build a frame")
}

/// A synthetic wrapped arm reply whose plaintext is `plaintext`.
///
/// The status is written at header offset 20, where it is plaintext even inside a wrapped frame.
pub fn capture_reply(session: &Session, status: u32, plaintext: &[u8]) -> Vec<u8> {
    let iv = fixed_iv();
    let ciphertext = crypto::encrypt_cbc(session.key().as_bytes(), &iv, plaintext);
    let mut body = frame::build_wrapped(
        cmd::ARM_CAPTURE,
        attr::CAPTURE,
        session.handle,
        &iv,
        plaintext.len() as u32,
        &ciphertext,
    );
    body[20..24].copy_from_slice(&status.to_le_bytes());
    body
}

/// A plaintext carrying the sample hash as `(u32 tag 0, u32 length 20, 20 bytes)`.
pub fn sample_hash_plaintext() -> Vec<u8> {
    let mut plaintext = vec![0u8; 8 + SAMPLE_HASH.len()];
    plaintext[4..8].copy_from_slice(&(SAMPLE_HASH.len() as u32).to_le_bytes());
    plaintext[8..].copy_from_slice(&SAMPLE_HASH);
    plaintext
}

/// The 20-byte value a synthetic `0x73` reply carries at plaintext `+32`.
pub const MATCH_VALUE: [u8; 20] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3,
];

/// Length of the `0x73` parameter block: five entries plus `(3, 20, template_id)`.
pub const MATCH_TLV_LEN: usize = 88;
/// Plaintext length the driver sends with `0x73`.
pub const MATCH_PLAINTEXT_LEN: usize = 128;

/// The documented 88-byte `0x73` parameter block, built independently of the implementation.
///
/// Five `(tag, 4, value)` entries followed by `(3, 20, template_id)`. The audited reference stops
/// after the final entry's eight-byte header; that 68-byte request was refused with `0x59` on
/// 2026-10-28, so the driver completes the value. `None` supplies twenty zero bytes.
pub fn match_tlv(handle: u32, template_id: Option<&[u8; 20]>) -> [u8; MATCH_TLV_LEN] {
    let mut tlv = [0u8; MATCH_TLV_LEN];
    let entries: [(usize, u32, u32); 5] = [
        (0, 0, handle),
        (12, 0, 0x148),
        (24, 0, 0x53e2),
        (36, 0, 0),
        (48, 2, 0x007b_0ad3),
    ];
    for (at, tag, value) in entries {
        tlv[at..at + 4].copy_from_slice(&tag.to_le_bytes());
        tlv[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes());
        tlv[at + 8..at + 12].copy_from_slice(&value.to_le_bytes());
    }
    tlv[60..64].copy_from_slice(&3u32.to_le_bytes());
    tlv[64..68].copy_from_slice(&20u32.to_le_bytes());
    if let Some(template_id) = template_id {
        tlv[68..88].copy_from_slice(template_id);
    }
    tlv
}

/// The exact wrapped `0x73` frame a match must send for `session` at its next sequence.
pub fn match_frame(session: &Session, iv: &[u8; 16]) -> Vec<u8> {
    match_frame_with(session, iv, None)
}

/// The exact wrapped `0x73` frame for `session` at its next sequence with a template id.
pub fn match_frame_with(
    session: &Session,
    iv: &[u8; 16],
    template_id: Option<&[u8; 20]>,
) -> Vec<u8> {
    match_frame_at_with(session, iv, session.next_sequence(), template_id)
}

/// The exact wrapped `0x73` frame for `session` at an explicit wrap sequence.
pub fn match_frame_at(session: &Session, iv: &[u8; 16], sequence: u32) -> Vec<u8> {
    match_frame_at_with(session, iv, sequence, None)
}

/// The exact wrapped `0x73` frame at an explicit sequence with a template id.
pub fn match_frame_at_with(
    session: &Session,
    iv: &[u8; 16],
    sequence: u32,
    template_id: Option<&[u8; 20]>,
) -> Vec<u8> {
    session
        .wrap(
            cmd::MATCH,
            attr::CAPTURE,
            &match_tlv(session.handle, template_id),
            MATCH_PLAINTEXT_LEN,
            iv,
            sequence,
        )
        .expect("the match constants build a frame")
}

/// A synthetic wrapped match reply whose plaintext is `plaintext`.
pub fn match_reply(session: &Session, status: u32, plaintext: &[u8]) -> Vec<u8> {
    let iv = fixed_iv();
    let ciphertext = crypto::encrypt_cbc(session.key().as_bytes(), &iv, plaintext);
    let mut body = frame::build_wrapped(
        cmd::MATCH,
        attr::CAPTURE,
        session.handle,
        &iv,
        plaintext.len() as u32,
        &ciphertext,
    );
    body[20..24].copy_from_slice(&status.to_le_bytes());
    body
}

/// A synthetic match plaintext: the verdict word at `+8`, and the optional value at `+32`.
///
/// Without a value the plaintext is 28 bytes, long enough for the word but too short for the
/// 20-byte value. Pass an explicit length through [`match_plaintext_with_len`] to exercise the
/// too-short-for-the-word case.
pub fn match_plaintext(word: u32, value: Option<&[u8; 20]>) -> Vec<u8> {
    match value {
        Some(_) => match_plaintext_with_len(word, value, 52),
        None => match_plaintext_with_len(word, None, 28),
    }
}

/// A synthetic match plaintext of exactly `len` bytes.
pub fn match_plaintext_with_len(word: u32, value: Option<&[u8; 20]>, len: usize) -> Vec<u8> {
    let mut plaintext = vec![0u8; len];
    if len >= 12 {
        plaintext[8..12].copy_from_slice(&word.to_le_bytes());
    }
    if let Some(value) = value
        && len >= 52
    {
        plaintext[32..52].copy_from_slice(value);
    }
    plaintext
}

/// Runs a handshake that keeps its handle, then the wrapped `0x02`, and returns the live session.
///
/// The scripted outcomes are pushed as each step is reached, so a caller can keep appending.
pub fn opened_session(transport: &mut ScriptedTransport) -> Session {
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: challenge_reply(0),
    });
    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: response_reply(0),
    });
    let mut handshake = Handshake::new(client_nonce(), host_key(), host_nonce()).keeping_handle();
    let session = run(&mut handshake, transport).expect("the handshake keeps its handle");

    transport.push(ScriptedOutcome::Reply {
        status: 0,
        body: open_reply(0),
    });
    let mut open = OpenSession::new(session, fixed_iv());
    run(&mut open, transport).expect("the scripted sensor opens the session")
}

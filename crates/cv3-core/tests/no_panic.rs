//! A deterministic corpus for the byte parsers that must never panic.
//!
//! This is the part of fuzzing that runs in the normal test suite: random buffers and structured
//! near-valid frames are fed to the same parsers the fuzz target uses. It does not replace a
//! libFuzzer run; it makes "malformed input never panics" a check that runs everywhere.

use cv3_core::frame::{self, HEADER_LEN};
use cv3_core::proto::{attr, cmd};
use cv3_core::session::SessionKey;
use cv3_core::transcript::{Transcript, TranscriptRecord};

fn exercise(bytes: &[u8]) {
    let _ = frame::Header::parse(bytes);
    let _ = frame::validate(bytes);
    let key = SessionKey::from_bytes([0x5a; 16]);
    let _ = key.unwrap(bytes);
    let _ = cv3_core::capture::find_tlv_value(bytes, 20);
    let _ = cv3_core::inventory::scan_tlv(bytes);
    let _ = Transcript::from_bytes(bytes);
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn random_buffers_never_panic() {
    let mut state = 0x1234_5678_9abc_def0u64;

    for _ in 0..20_000 {
        let length = (next(&mut state) % 513) as usize;
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            *byte = (next(&mut state) >> 24) as u8;
        }
        exercise(&bytes);
    }
}

#[test]
fn near_valid_frames_and_wrapped_bodies_never_panic() {
    let plain = frame::build_plain(cmd::VERIFY, attr::CAPTURE, 7, &[0xAB; 32]);
    let iv = [0x11u8; 16];

    // Every truncation of a valid frame.
    for length in 0..=plain.len() {
        exercise(&plain[..length]);
    }

    // One altered byte at every position, and a few structural corruptions.
    for position in 0..plain.len() {
        let mut altered = plain.clone();
        altered[position] ^= 0xFF;
        exercise(&altered);
    }
    for declared in [0u32, 1, 43, 44, u32::MAX] {
        let mut altered = plain.clone();
        altered[4..8].copy_from_slice(&declared.to_le_bytes());
        exercise(&altered);
    }
    for magic in [0u32, 2, u32::MAX] {
        let mut altered = plain.clone();
        altered[0..4].copy_from_slice(&magic.to_le_bytes());
        exercise(&altered);
    }

    // Wrapped bodies at every block alignment, including empty and unaligned ciphertexts.
    for length in 0..=48 {
        let ciphertext = vec![0x22u8; length];
        let wrapped = frame::build_wrapped(
            cmd::VERIFY,
            attr::CAPTURE,
            7,
            &iv,
            (length / 2) as u32,
            &ciphertext,
        );
        exercise(&wrapped);
    }
    let oversized =
        frame::build_wrapped(cmd::VERIFY, attr::CAPTURE, 7, &iv, 0, &vec![0x22u8; 5_000]);
    exercise(&oversized);

    // A wrapped body whose header claims a length the buffer cannot hold.
    let mut lying = plain;
    lying[11] = 0x02;
    lying[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    exercise(&lying);
}

#[test]
fn random_bytes_that_start_like_a_header_never_panic() {
    let mut state = 0x0fed_cba9_8765_4321u64;

    for _ in 0..5_000 {
        let mut bytes = vec![0u8; HEADER_LEN + (next(&mut state) % 256) as usize];
        let length = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        for byte in &mut bytes[8..] {
            *byte = (next(&mut state) >> 16) as u8;
        }
        // Half the corpus claims to be a wrapped reply, so the unwrap path is exercised too. Both
        // accepted encodings are covered: 0x02 on commands, 0x03 on replies.
        if next(&mut state) & 1 == 0 {
            bytes[11] = if next(&mut state) & 1 == 0 {
                0x02
            } else {
                0x03
            };
            let iv = [0x33u8; 16];
            bytes[24..40].copy_from_slice(&iv);
        }
        exercise(&bytes);
    }
}

#[test]
fn corrupt_transcripts_never_panic() {
    let mut transcript = Transcript::new("handshake");
    transcript.push(TranscriptRecord::HostFrame(frame::build_plain(
        cmd::CHALLENGE,
        attr::CHALLENGE,
        0,
        &[0u8; 24],
    )));
    transcript.push(TranscriptRecord::Reply {
        status: 0,
        body: vec![1, 2, 3],
    });
    transcript.push(TranscriptRecord::Finger);
    transcript.push(TranscriptRecord::Transport(
        cv3_core::TransportError::Other("boom".to_owned()),
    ));
    let bytes = transcript.to_bytes();

    for length in 0..=bytes.len() {
        let _ = Transcript::from_bytes(&bytes[..length]);
    }
    for position in 0..bytes.len() {
        for value in [0x00u8, 0x7F, 0xFF] {
            let mut altered = bytes.clone();
            altered[position] = value;
            let _ = Transcript::from_bytes(&altered);
        }
    }
}

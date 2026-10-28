//! The `0x23` / `0x24` handshake: ECDH, the key schedule, and handle teardown.
//!
//! ```text
//! host → sensor  0x23  client nonce (20) || u32 1
//! sensor → host        reply: device public key (64) at body[44..108],
//!                              opaque certificate (64) at body[108..172],
//!                              device nonce (20) at body[172..192];
//!                              handle is the reply header's handle
//! host → sensor  0x24  host nonce (20) || host public key X||Y (64)
//! sensor → host        reply: status 0 means accepted
//!
//! Z          = ECDH(host secret, device public key)       32-byte X coordinate
//! master     = SHA1(Z)                                    20 bytes
//! sessionKey = SHA1(master || device nonce || host nonce)[..16]
//! ```
//!
//! The client nonce from `0x23` is not in the schedule. The sensor does not authenticate the host,
//! so the probe generates a fresh host keypair per run and nothing is stored.
//!
//! The sensor allocates the session handle during `0x23`. A handshake that fails after the handle
//! was learned, and a successful handshake, both send the close-session frame before finishing, so
//! no handle is left dangling across reboots. Teardown is best effort: a failure to send or read
//! the close reply never replaces the handshake's own result.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, HostKey};
use crate::event::{Action, Event, TransportError};
use crate::frame::{self, FrameError, HEADER_LEN};
use crate::operation::Operation;
use crate::proto::{attr, cmd};

/// Length of every nonce in the handshake: client, device and host.
pub const NONCE_LEN: usize = 20;
/// Length of the device's P-256 public key (`X || Y`).
pub const DEVICE_PUBLIC_LEN: usize = 64;
/// Length of the whole `0x23` reply body: 44-byte header plus 148 parameter bytes.
pub const CHALLENGE_REPLY_LEN: usize = HEADER_LEN + 148;
/// Length of the derived AES-128 session key.
pub const SESSION_KEY_LEN: usize = crypto::SESSION_KEY_LEN;

const DEVICE_PUBLIC_OFFSET: usize = HEADER_LEN;
const DEVICE_NONCE_OFFSET: usize = HEADER_LEN + 128;

/// The derived session key, zeroed when dropped.
///
/// It has no `Clone`, no `Copy`, and its `Debug` output is redacted; the bytes leave the core only
/// through [`Self::as_bytes`], which the probe uses behind an explicit flag.
pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }

    /// A short, non-secret identifier for the key: `SHA-256(key)[..8]`.
    pub fn fingerprint(&self) -> [u8; 8] {
        let digest = Sha256::digest(self.0);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What a completed handshake learned.
#[derive(Debug)]
pub struct Session {
    /// The session handle the sensor allocated in its `0x23` reply. The handshake has already sent
    /// the close-session frame before returning (teardown is best effort); the value remains useful
    /// for the probe's output and for tests.
    pub handle: u32,
    /// Length of the client nonce sent in `0x23`.
    pub client_nonce_len: usize,
    /// Length of the device nonce read from the `0x23` reply.
    pub device_nonce_len: usize,
    /// Length of the host nonce sent in `0x24`.
    pub host_nonce_len: usize,
    key: SessionKey,
}

impl Session {
    /// The derived session key.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Takes the session key, leaving the rest of the record.
    pub fn into_key(self) -> SessionKey {
        self.key
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
            && self.client_nonce_len == other.client_nonce_len
            && self.device_nonce_len == other.device_nonce_len
            && self.host_nonce_len == other.host_nonce_len
            && self.key.0 == other.key.0
    }
}

impl Eq for Session {}

/// Why a handshake did not produce a session key.
///
/// Every variant is distinct on purpose: a caller can tell a refused challenge from a damaged
/// reply without inspecting bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The sensor answered `0x23` with a non-zero status.
    RejectedChallenge(u32),
    /// The sensor answered `0x24` with a non-zero status.
    RejectedResponse(u32),
    /// A reply is too short to carry what the handshake reads.
    ShortReply { got: usize, need: usize },
    /// A reply is longer than the fixed handshake body.
    OversizedReply { got: usize, max: usize },
    /// A reply's header does not validate.
    MalformedFrame(FrameError),
    /// The device's public key is not a valid P-256 point.
    InvalidDeviceKey,
    /// The transport failed before the handshake completed.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RejectedChallenge(status) => write!(
                f,
                "sensor rejected the 0x23 challenge with status {status:#04x}"
            ),
            Self::RejectedResponse(status) => write!(
                f,
                "sensor rejected the 0x24 response with status {status:#04x}"
            ),
            Self::ShortReply { got, need } => write!(f, "reply is {got} bytes, needs {need}"),
            Self::OversizedReply { got, max } => {
                write!(f, "reply is {got} bytes, more than the {max} allowed")
            }
            Self::MalformedFrame(error) => write!(f, "malformed reply frame: {error}"),
            Self::InvalidDeviceKey => f.write_str("device public key is not a valid P-256 point"),
            Self::Transport(error) => write!(f, "transport failed: {error}"),
            Self::Cancelled => f.write_str("handshake cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event during the handshake"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for HandshakeError {}

#[derive(Debug)]
enum State {
    NotStarted,
    WaitingChallengeReply,
    WaitingResponseReply,
    /// The handle is being released; the handshake's own result is held until the close reply.
    ReleasingHandle {
        outcome: Result<Session, HandshakeError>,
    },
    Done,
}

type Outcome = Result<Session, HandshakeError>;

/// The handshake operation, driven only by [`Operation::start`] and [`Operation::step`].
pub struct Handshake {
    client_nonce: [u8; NONCE_LEN],
    host_nonce: [u8; NONCE_LEN],
    host_key: HostKey,
    handle: u32,
    device_public: [u8; DEVICE_PUBLIC_LEN],
    device_nonce: [u8; NONCE_LEN],
    state: State,
}

impl Handshake {
    /// Builds a handshake from the probe's randomness. `host_key` is the fresh ephemeral keypair.
    pub fn new(
        client_nonce: [u8; NONCE_LEN],
        host_key: HostKey,
        host_nonce: [u8; NONCE_LEN],
    ) -> Self {
        Self {
            client_nonce,
            host_nonce,
            host_key,
            handle: 0,
            device_public: [0u8; DEVICE_PUBLIC_LEN],
            device_nonce: [0u8; NONCE_LEN],
            state: State::NotStarted,
        }
    }

    fn challenge_frame(&self) -> Vec<u8> {
        let mut param = [0u8; 24];
        param[..NONCE_LEN].copy_from_slice(&self.client_nonce);
        param[NONCE_LEN..].copy_from_slice(&1u32.to_le_bytes());
        frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &param)
    }

    fn response_frame(&self) -> Vec<u8> {
        let mut param = [0u8; 84];
        param[..NONCE_LEN].copy_from_slice(&self.host_nonce);
        param[NONCE_LEN..].copy_from_slice(&self.host_key.public_key());
        frame::build_plain(
            cmd::CHALLENGE_RESPONSE,
            attr::CHALLENGE_RESPONSE,
            self.handle,
            &param,
        )
    }

    fn finish(&mut self, outcome: Outcome) -> Action<Outcome> {
        self.state = State::Done;
        Action::Finish(outcome)
    }

    /// Releases a learned handle before finishing. With no handle there is nothing to release.
    fn release_then_finish(&mut self, outcome: Outcome) -> Action<Outcome> {
        if self.handle == 0 {
            return self.finish(outcome);
        }
        self.state = State::ReleasingHandle { outcome };
        Action::Send(frame::build_close_handle(self.handle))
    }

    fn on_challenge_reply(&mut self, status: u32, body: Vec<u8>) -> Action<Outcome> {
        let header = match frame::validate(&body) {
            Ok(header) => header,
            Err(error) => return self.finish(Err(HandshakeError::MalformedFrame(error))),
        };
        if status != 0 {
            return self.finish(Err(HandshakeError::RejectedChallenge(status)));
        }
        if body.len() < CHALLENGE_REPLY_LEN {
            return self.finish(Err(HandshakeError::ShortReply {
                got: body.len(),
                need: CHALLENGE_REPLY_LEN,
            }));
        }
        if body.len() > CHALLENGE_REPLY_LEN {
            return self.finish(Err(HandshakeError::OversizedReply {
                got: body.len(),
                max: CHALLENGE_REPLY_LEN,
            }));
        }

        self.handle = header.handle;
        self.device_public
            .copy_from_slice(&body[DEVICE_PUBLIC_OFFSET..DEVICE_PUBLIC_OFFSET + DEVICE_PUBLIC_LEN]);
        self.device_nonce
            .copy_from_slice(&body[DEVICE_NONCE_OFFSET..DEVICE_NONCE_OFFSET + NONCE_LEN]);

        self.state = State::WaitingResponseReply;
        Action::Send(self.response_frame())
    }

    fn on_response_reply(&mut self, status: u32, body: Vec<u8>) -> Action<Outcome> {
        if let Err(error) = frame::validate(&body) {
            return self.release_then_finish(Err(HandshakeError::MalformedFrame(error)));
        }
        if status != 0 {
            return self.release_then_finish(Err(HandshakeError::RejectedResponse(status)));
        }
        match self.derive() {
            Ok(session) => self.release_then_finish(Ok(session)),
            Err(error) => self.release_then_finish(Err(error)),
        }
    }

    fn derive(&self) -> Outcome {
        let shared = Zeroizing::new(
            self.host_key
                .ecdh(&self.device_public)
                .map_err(|_| HandshakeError::InvalidDeviceKey)?,
        );
        let master = Zeroizing::new(crypto::sha1(&shared[..]));

        let mut input = Zeroizing::new([0u8; SHA1_INPUT_LEN]);
        input[..crypto::SHA1_LEN].copy_from_slice(&master[..]);
        input[crypto::SHA1_LEN..crypto::SHA1_LEN + NONCE_LEN].copy_from_slice(&self.device_nonce);
        input[crypto::SHA1_LEN + NONCE_LEN..].copy_from_slice(&self.host_nonce);
        let digest = Zeroizing::new(crypto::sha1(&input[..]));

        let mut key = [0u8; SESSION_KEY_LEN];
        key.copy_from_slice(&digest[..SESSION_KEY_LEN]);

        Ok(Session {
            handle: self.handle,
            client_nonce_len: NONCE_LEN,
            device_nonce_len: self.device_nonce.len(),
            host_nonce_len: self.host_nonce.len(),
            key: SessionKey(key),
        })
    }
}

const SHA1_INPUT_LEN: usize = crypto::SHA1_LEN + NONCE_LEN + NONCE_LEN;

impl Operation for Handshake {
    type Output = Outcome;

    fn start(&mut self) -> Action<Outcome> {
        if matches!(self.state, State::NotStarted) {
            self.state = State::WaitingChallengeReply;
            Action::Send(self.challenge_frame())
        } else {
            self.finish(Err(HandshakeError::AlreadyFinished))
        }
    }

    fn step(&mut self, event: Event) -> Action<Outcome> {
        let state = std::mem::replace(&mut self.state, State::Done);
        match state {
            State::NotStarted => self.finish(Err(HandshakeError::UnexpectedEvent)),
            State::WaitingChallengeReply => match event {
                Event::Reply { status, body } => self.on_challenge_reply(status, body),
                Event::ReplyWithoutBody => self.finish(Err(HandshakeError::ShortReply {
                    got: 0,
                    need: CHALLENGE_REPLY_LEN,
                })),
                Event::Transport(error) => self.finish(Err(HandshakeError::Transport(error))),
                Event::Cancelled => self.finish(Err(HandshakeError::Cancelled)),
                Event::Finger => self.finish(Err(HandshakeError::UnexpectedEvent)),
            },
            State::WaitingResponseReply => match event {
                Event::Reply { status, body } => self.on_response_reply(status, body),
                Event::ReplyWithoutBody => {
                    self.release_then_finish(Err(HandshakeError::ShortReply {
                        got: 0,
                        need: HEADER_LEN,
                    }))
                }
                Event::Transport(error) => {
                    self.release_then_finish(Err(HandshakeError::Transport(error)))
                }
                Event::Cancelled => self.release_then_finish(Err(HandshakeError::Cancelled)),
                Event::Finger => self.release_then_finish(Err(HandshakeError::UnexpectedEvent)),
            },
            // Teardown is best effort: whatever the close reply says, the handshake's own outcome
            // stands. A transport failure here cannot be recovered anyway.
            State::ReleasingHandle { outcome } => self.finish(outcome),
            State::Done => self.finish(Err(HandshakeError::AlreadyFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: u32 = 0x1122_3344;

    // RFC 5903, section 8.1: the initiator's scalar and public key.
    fn host_secret() -> [u8; 32] {
        unhex::<32>(
            "c88f01f510d9ac3f70a292daa2316de5
             44e9aab8afe84049c62a9c57862d1433",
        )
    }

    fn host_public() -> [u8; 64] {
        unhex::<64>(
            "dad0b65394221cf9b051e1feca5787d0
             98dfe637fc90b9ef945d0c3772581180
             5271a0461cdb8252d61f1c456fa3e59a
             b1f45b33accf5f58389e0577b8990bb3",
        )
    }

    // RFC 5903, section 8.1: the responder's public key, used here as the device's.
    fn device_public() -> [u8; 64] {
        unhex::<64>(
            "d12dfb5289c8d4f81208b70270398c34
             2296970a0bccb74c736fc7554494bf63
             56fbf3ca366cc23e8157854c13c58d6a
             ac23f046ada30f8353e74f33039872ab",
        )
    }

    fn device_nonce() -> [u8; NONCE_LEN] {
        unhex::<NONCE_LEN>("000102030405060708090a0b0c0d0e0f10111213")
    }

    fn host_nonce() -> [u8; NONCE_LEN] {
        unhex::<NONCE_LEN>("202122232425262728292a2b2c2d2e2f30313233")
    }

    fn client_nonce() -> [u8; NONCE_LEN] {
        unhex::<NONCE_LEN>("404142434445464748494a4b4c4d4e4f50515253")
    }

    fn other_client_nonce() -> [u8; NONCE_LEN] {
        unhex::<NONCE_LEN>("606162636465666768696a6b6c6d6e6f70717273")
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
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

    fn handshake(client: [u8; NONCE_LEN]) -> Handshake {
        Handshake::new(
            client,
            HostKey::from_bytes(&host_secret()).expect("RFC scalar"),
            host_nonce(),
        )
    }

    fn challenge_reply(status: u32) -> Vec<u8> {
        let mut param = [0u8; 148];
        param[..DEVICE_PUBLIC_LEN].copy_from_slice(&device_public());
        param[DEVICE_PUBLIC_LEN..DEVICE_PUBLIC_LEN + 64].fill(0xcc);
        param[128..].copy_from_slice(&device_nonce());
        frame::build_plain_reply(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, status, &param)
    }

    fn response_reply(status: u32) -> Vec<u8> {
        frame::build_plain_reply(
            cmd::CHALLENGE_RESPONSE,
            attr::CHALLENGE_RESPONSE,
            HANDLE,
            status,
            &[],
        )
    }

    fn expect_send(action: Action<Outcome>) -> Vec<u8> {
        match action {
            Action::Send(frame) => frame,
            other => panic!("expected a send, got {other:?}"),
        }
    }

    fn expect_finish(action: Action<Outcome>) -> Outcome {
        match action {
            Action::Finish(outcome) => outcome,
            other => panic!("expected a finish, got {other:?}"),
        }
    }

    #[test]
    fn success_sends_the_documented_frames_and_derives_the_vector_key() {
        let mut operation = handshake(client_nonce());

        let challenge = expect_send(operation.start());
        let mut expected_challenge = [0u8; 24];
        expected_challenge[..NONCE_LEN].copy_from_slice(&client_nonce());
        expected_challenge[NONCE_LEN..].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            challenge,
            frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &expected_challenge)
        );

        let response = expect_send(operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        }));
        let mut expected_response = [0u8; 84];
        expected_response[..NONCE_LEN].copy_from_slice(&host_nonce());
        expected_response[NONCE_LEN..].copy_from_slice(&host_public());
        assert_eq!(
            response,
            frame::build_plain(
                cmd::CHALLENGE_RESPONSE,
                attr::CHALLENGE_RESPONSE,
                HANDLE,
                &expected_response
            )
        );

        let close = expect_send(operation.step(Event::Reply {
            status: 0,
            body: response_reply(0),
        }));
        assert_eq!(close, frame::build_close_handle(HANDLE));

        let session = expect_finish(operation.step(Event::ReplyWithoutBody)).expect("success");
        assert_eq!(session.handle, HANDLE);
        assert_eq!(session.client_nonce_len, NONCE_LEN);
        assert_eq!(session.device_nonce_len, NONCE_LEN);
        assert_eq!(session.host_nonce_len, NONCE_LEN);
        // Constructed from the protocol description with RFC 5903's shared secret and
        // SHA-1(master || device nonce || host nonce)[..16].
        assert_eq!(
            session.key().as_bytes(),
            &unhex::<16>("6352f380005c4ebf33ce5ae1aad71e6f")
        );
        assert_eq!(session.key().fingerprint(), unhex::<8>("a4af006861543884"));
    }

    #[test]
    fn the_client_nonce_does_not_influence_the_key_schedule() {
        fn key_for(client: [u8; NONCE_LEN]) -> [u8; 16] {
            let mut operation = handshake(client);
            let _ = operation.start();
            let _ = operation.step(Event::Reply {
                status: 0,
                body: challenge_reply(0),
            });
            let _ = operation.step(Event::Reply {
                status: 0,
                body: response_reply(0),
            });
            let session = expect_finish(operation.step(Event::ReplyWithoutBody)).expect("success");
            *session.key().as_bytes()
        }

        assert_eq!(key_for(client_nonce()), key_for(other_client_nonce()));
    }

    #[test]
    fn a_teardown_failure_does_not_discard_a_derived_key() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });
        let _ = operation.step(Event::Reply {
            status: 0,
            body: response_reply(0),
        });

        // The close reply is best effort: its status never replaces the handshake's result.
        let session = expect_finish(operation.step(Event::Reply {
            status: 0x0b,
            body: response_reply(0x0b),
        }))
        .expect("the key was already derived");

        assert_eq!(
            session.key().as_bytes(),
            &unhex::<16>("6352f380005c4ebf33ce5ae1aad71e6f")
        );
    }

    #[test]
    fn a_rejected_challenge_is_distinct_and_never_sends_a_close() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        let outcome = expect_finish(operation.step(Event::Reply {
            status: 0x0c,
            body: challenge_reply(0x0c),
        }));

        assert_eq!(outcome, Err(HandshakeError::RejectedChallenge(0x0c)));
    }

    #[test]
    fn a_short_challenge_reply_is_distinct() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let short = frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, &[]);

        let outcome = expect_finish(operation.step(Event::Reply {
            status: 0,
            body: short,
        }));

        assert_eq!(
            outcome,
            Err(HandshakeError::ShortReply {
                got: HEADER_LEN,
                need: CHALLENGE_REPLY_LEN,
            })
        );
    }

    #[test]
    fn a_no_body_challenge_reply_is_a_short_reply() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(HandshakeError::ShortReply {
                got: 0,
                need: CHALLENGE_REPLY_LEN,
            })
        );
    }

    #[test]
    fn a_malformed_magic_is_distinct_and_panic_free() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let mut body = challenge_reply(0);
        body[0] = 9;

        assert_eq!(
            expect_finish(operation.step(Event::Reply { status: 0, body })),
            Err(HandshakeError::MalformedFrame(FrameError::BadMagic(9)))
        );
    }

    #[test]
    fn an_absurd_declared_length_is_distinct_and_panic_free() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let mut body = challenge_reply(0);
        body[4..8].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            expect_finish(operation.step(Event::Reply { status: 0, body })),
            Err(HandshakeError::MalformedFrame(
                FrameError::LengthMismatch { .. }
            ))
        ));
    }

    #[test]
    fn an_oversized_challenge_reply_is_rejected() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let body = frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, &[0u8; 149]);

        assert_eq!(
            expect_finish(operation.step(Event::Reply { status: 0, body })),
            Err(HandshakeError::OversizedReply {
                got: CHALLENGE_REPLY_LEN + 1,
                max: CHALLENGE_REPLY_LEN,
            })
        );
    }

    #[test]
    fn a_status_error_on_the_response_releases_the_handle_first() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });

        let close = expect_send(operation.step(Event::Reply {
            status: 0x09,
            body: response_reply(0x09),
        }));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(HandshakeError::RejectedResponse(0x09))
        );
    }

    #[test]
    fn a_transport_failure_before_the_handle_is_learned_finishes_at_once() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Timeout))),
            Err(HandshakeError::Transport(TransportError::Timeout))
        );
    }

    #[test]
    fn a_transport_failure_after_the_handle_is_learned_releases_it() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });

        let close = expect_send(operation.step(Event::Transport(TransportError::Disconnected)));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Disconnected))),
            Err(HandshakeError::Transport(TransportError::Disconnected))
        );
    }

    #[test]
    fn cancellation_after_the_handle_is_learned_releases_it() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });

        let close = expect_send(operation.step(Event::Cancelled));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::Cancelled)),
            Err(HandshakeError::Cancelled)
        );
    }

    #[test]
    fn cancellation_before_the_handle_is_learned_finishes_at_once() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::Cancelled)),
            Err(HandshakeError::Cancelled)
        );
    }

    #[test]
    fn a_malformed_response_releases_the_known_handle() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });
        let mut body = response_reply(0);
        body[0] = 0;

        let close = expect_send(operation.step(Event::Reply { status: 0, body }));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert!(matches!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(HandshakeError::MalformedFrame(FrameError::BadMagic(0)))
        ));
    }

    #[test]
    fn an_invalid_device_key_releases_the_handle_and_is_distinct() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let mut body = challenge_reply(0);
        body[DEVICE_PUBLIC_OFFSET..DEVICE_PUBLIC_OFFSET + DEVICE_PUBLIC_LEN].fill(0);
        let _ = operation.step(Event::Reply { status: 0, body });

        let close = expect_send(operation.step(Event::Reply {
            status: 0,
            body: response_reply(0),
        }));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(HandshakeError::InvalidDeviceKey)
        );
    }

    #[test]
    fn a_no_body_response_is_a_short_reply_and_releases_the_handle() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });

        let close = expect_send(operation.step(Event::ReplyWithoutBody));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(HandshakeError::ShortReply {
                got: 0,
                need: HEADER_LEN,
            })
        );
    }

    #[test]
    fn an_unexpected_finger_event_is_distinct_and_panic_free() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::Finger)),
            Err(HandshakeError::UnexpectedEvent)
        );
    }

    #[test]
    fn stepping_after_finish_returns_an_error_instead_of_panicking() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: challenge_reply(0),
        });
        let _ = operation.step(Event::Reply {
            status: 0,
            body: response_reply(0),
        });
        let _ = expect_finish(operation.step(Event::ReplyWithoutBody));

        assert_eq!(
            expect_finish(operation.step(Event::Cancelled)),
            Err(HandshakeError::AlreadyFinished)
        );
        assert_eq!(
            expect_finish(operation.step(Event::Finger)),
            Err(HandshakeError::AlreadyFinished)
        );
    }

    #[test]
    fn a_second_start_is_refused_without_panicking() {
        let mut operation = handshake(client_nonce());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.start()),
            Err(HandshakeError::AlreadyFinished)
        );
    }
}

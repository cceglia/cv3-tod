//! The secure session: its credentials, wrapped-command framing, and lifecycle operations.
//!
//! A session begins when the handshake derives a key and the sensor allocates a handle (see
//! [`crate::handshake`]). Every fingerprint command is then sent **wrapped**: a 44-byte header
//! followed by AES-128-CBC ciphertext. The plaintext is
//!
//! ```text
//! TLV || HMAC-SHA-256(macKey, header(44) || TLV || u32le(seq)) || zero padding
//! ```
//!
//! padded to exactly `plaintext_len` bytes and then PKCS#7-padded, so the ciphertext is
//! `((plaintext_len / 16) + 1) * 16` bytes. `macKey` is `SHA-256("CV secure session blob\0")`, a
//! fixed constant published in the protocol: the token proves the frame was built by something
//! that knows the protocol, not who built it. Replies carry no token, so a genuine reply can be
//! replayed.
//!
//! The wrap sequence is a per-session counter: the wrapped `0x02` open consumes zero, and each
//! wrapped command advances it according to `advances_sequence`, the single copy of the rule.
//! Unwrapped commands (`0x23`, `0x24`, `0x04`, `0x8A`, `0x68`) never touch it.
//!
//! The module also owns the session lifecycle operations: [`OpenSession`] sends the wrapped
//! `0x02`, [`CloseSession`] releases the handle with the plain `0x04`, and [`Teardown`] cancels a
//! possibly-armed capture with the sessionless `0x68` before closing. All are driven through the
//! same [`Operation`] seam as the handshake.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError};
use crate::event::{Action, Event, TransportError};
use crate::frame::{self, FrameError, HEADER_LEN, Header, IV_OFFSET};
use crate::operation::Operation;
use crate::proto::{self, Encoding, attr, cmd};

/// Length of the AES-128 session key.
pub const SESSION_KEY_LEN: usize = crypto::SESSION_KEY_LEN;
/// Length of the wrapped frame's integrity token.
pub const TOKEN_LEN: usize = 32;
/// The published seed whose SHA-256 is the MAC key. Its 23 bytes include the terminating NUL.
pub const MAC_SEED: &[u8] = b"CV secure session blob\0";
/// Length of the MAC key.
pub const MAC_KEY_LEN: usize = 32;
/// Largest plaintext a wrapped command may carry, before PKCS#7 padding.
pub const MAX_PLAINTEXT_LEN: usize = 4096;
/// Largest ciphertext [`SessionKey::unwrap`] will decrypt.
pub const MAX_CIPHERTEXT_LEN: usize = 4096;

/// The 36-byte parameter block of the `0x02` open command: four TLVs selecting the application
/// scope, as the reference sends them.
pub const OPEN_TLV: [u8; 36] = [
    0, 0, 0, 0, 4, 0, 0, 0, 0x4f, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0,
];
/// Plaintext length the reference sends with `0x02`: four AES blocks plus one padding block.
pub const OPEN_PLAINTEXT_LEN: usize = 80;

/// The MAC key derived from the protocol's published seed.
pub fn mac_key() -> [u8; MAC_KEY_LEN] {
    crypto::sha256(MAC_SEED)
}

/// The session key. It is zeroed on drop, has no `Clone`, and redacts itself from `Debug`.
pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    /// Wraps raw key bytes; only the handshake and tests construct one.
    pub(crate) fn new(bytes: [u8; SESSION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Builds a key from raw bytes, for test support and the fuzz target.
    ///
    /// The protocol's real key is derived by the handshake and nothing in the driver calls this.
    /// It exists so a reply parser can be fed arbitrary device bytes without a hardware session.
    pub fn from_bytes(bytes: [u8; SESSION_KEY_LEN]) -> Self {
        Self(bytes)
    }

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

    /// Validates and decrypts one wrapped reply.
    ///
    /// Lengths are device-controlled, so every bound is checked before slicing or decrypting. The
    /// ciphertext must be non-empty, a whole number of blocks, and no longer than
    /// [`MAX_CIPHERTEXT_LEN`]; PKCS#7 padding must be well formed.
    ///
    /// Both wrapped encodings are accepted: `0x02`, which the host uses on commands, and `0x03`,
    /// which the sensor was measured to use on replies (see [`Encoding::WrappedReply`]). The body
    /// is laid out the same either way. Any other encoding is refused.
    pub fn unwrap(&self, body: &[u8]) -> Result<UnwrappedReply, UnwrapError> {
        let header = frame::validate(body).map_err(UnwrapError::Frame)?;
        if !Encoding::is_wrapped(header.encoding) {
            return Err(UnwrapError::UnexpectedEncoding(header.encoding));
        }

        let ciphertext = &body[HEADER_LEN..];
        if ciphertext.is_empty() {
            return Err(UnwrapError::EmptyCiphertext);
        }
        if !ciphertext.len().is_multiple_of(crypto::BLOCK_LEN) {
            return Err(UnwrapError::CiphertextNotAligned {
                got: ciphertext.len(),
            });
        }
        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(UnwrapError::CiphertextTooLarge {
                got: ciphertext.len(),
                max: MAX_CIPHERTEXT_LEN,
            });
        }

        let mut iv = [0u8; crypto::BLOCK_LEN];
        iv.copy_from_slice(&body[IV_OFFSET..IV_OFFSET + crypto::BLOCK_LEN]);
        let plaintext =
            crypto::decrypt_cbc(self.as_bytes(), &iv, ciphertext).map_err(UnwrapError::Crypto)?;
        Ok(UnwrappedReply { header, plaintext })
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

/// A live secure session: the handle the sensor allocated, the key the handshake derived, and the
/// wrap sequence the next wrapped command must carry.
///
/// The key is private and never appears in `Debug`. The type is movable but not clonable, so a
/// caller that receives one owns the only copy. Whether its handle is still open depends on the
/// handshake that produced it: [`crate::handshake::Handshake::new`] closes the handle, while
/// [`crate::handshake::Handshake::keeping_handle`] leaves it for [`OpenSession`].
#[derive(Debug)]
pub struct Session {
    /// The session handle from the `0x23` reply.
    pub handle: u32,
    /// Length of the client nonce sent in `0x23` (informational).
    pub client_nonce_len: usize,
    /// Length of the device nonce read from the `0x23` reply (informational).
    pub device_nonce_len: usize,
    /// Length of the host nonce sent in `0x24` (informational).
    pub host_nonce_len: usize,
    key: SessionKey,
    next_sequence: u32,
    sequence_rule: SequenceRule,
}

impl Session {
    /// Builds a session from freshly derived material. The handshake passes sequence zero; the
    /// probe's diagnostics may start anywhere.
    pub(crate) fn new(
        handle: u32,
        client_nonce_len: usize,
        device_nonce_len: usize,
        host_nonce_len: usize,
        key: SessionKey,
        next_sequence: u32,
    ) -> Self {
        Self {
            handle,
            client_nonce_len,
            device_nonce_len,
            host_nonce_len,
            key,
            next_sequence,
            sequence_rule: SequenceRule::SHIPPED,
        }
    }

    /// Replaces the wrap-sequence reading.
    ///
    /// Test support: the scripted-transport scenarios reproduce the reference's capture-pending
    /// retry under both readings without a second copy of the rule. The shipping code never calls
    /// this; the shipped reading is [`SequenceRule::SHIPPED`].
    pub fn with_sequence_rule(mut self, rule: SequenceRule) -> Self {
        self.sequence_rule = rule;
        self
    }

    /// The derived session key.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Takes the session key, leaving the rest of the record.
    pub fn into_key(self) -> SessionKey {
        self.key
    }

    /// The sequence the next wrapped command must carry.
    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    /// Sets the wrap sequence the next command will carry.
    ///
    /// Measurement override for `cvctl cancel-then-verify --rearm-sequence N`: the sensor rejects
    /// a re-arm at the reference sequence and at the next one, so the probe must be able to try
    /// another value without a second implementation of the session.
    pub fn set_next_sequence(&mut self, sequence: u32) {
        self.next_sequence = sequence;
    }

    /// Rewinds the wrap sequence by one.
    ///
    /// **Measured behaviour of this sensor, 2026-10-28, superseded 2026-10-29.** The earlier run
    /// saw a re-arm at N succeed after a mid-session `0x68`; on 2026-10-29 the same sequence and
    /// N+1 were both rejected with `0x0F`, and N+2 was accepted. The sensor therefore expects the
    /// cancel reply to have advanced the sequence, and the probe's default rewind is wrong for this
    /// firmware. `cvctl cancel-then-verify --rearm-sequence N` can try any value; see
    /// `docs/protocol-notes.md` for the full run, including that the verify after an N+2 re-arm
    /// timed out and wedged the sensor. The shipping plugin never re-arms: it closes the session
    /// after a cancel.
    ///
    /// The caller invokes this only after a wrapped reply that advanced the counter (the arm's
    /// `0x00` or `0x85` with a body), so the counter never starts at zero here.
    pub fn rewind_sequence(&mut self) {
        self.next_sequence = self.next_sequence.wrapping_sub(1);
    }

    /// Builds one wrapped session command.
    ///
    /// The header is built first, with its final total length and IV, because the token covers it.
    /// The plaintext is exactly `plaintext_len` bytes (`tlv` followed by the token followed by
    /// zeros), which PKCS#7 then pads to `plaintext_len + 16` bytes. The frame is the header
    /// followed by that ciphertext.
    pub fn wrap(
        &self,
        cmd: u16,
        attr: u8,
        tlv: &[u8],
        plaintext_len: usize,
        iv: &[u8; crypto::BLOCK_LEN],
        seq: u32,
    ) -> Result<Vec<u8>, WrapError> {
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(WrapError::PlaintextTooLarge {
                plaintext_len,
                max: MAX_PLAINTEXT_LEN,
            });
        }
        if tlv.len() + TOKEN_LEN > plaintext_len {
            return Err(WrapError::PlaintextTooShort {
                plaintext_len,
                tlv_len: tlv.len(),
            });
        }

        // PKCS#7 always adds one block when the plaintext is block aligned, and pads a partial
        // block to the next one. Building the frame now fixes the header the token covers.
        let ciphertext_len = (plaintext_len / crypto::BLOCK_LEN + 1) * crypto::BLOCK_LEN;
        let placeholder = vec![0u8; ciphertext_len];
        let mut frame =
            frame::build_wrapped(cmd, attr, self.handle, iv, tlv.len() as u32, &placeholder);

        let mut mac_input = Zeroizing::new(Vec::with_capacity(HEADER_LEN + tlv.len() + 4));
        mac_input.extend_from_slice(&frame[..HEADER_LEN]);
        mac_input.extend_from_slice(tlv);
        mac_input.extend_from_slice(&seq.to_le_bytes());
        let token = crypto::hmac_sha256(&mac_key(), &mac_input);

        let mut plaintext = Zeroizing::new(vec![0u8; plaintext_len]);
        plaintext[..tlv.len()].copy_from_slice(tlv);
        plaintext[tlv.len()..tlv.len() + TOKEN_LEN].copy_from_slice(&token);

        let ciphertext = crypto::encrypt_cbc(self.key.as_bytes(), iv, &plaintext);
        debug_assert_eq!(ciphertext.len(), ciphertext_len, "PKCS#7 adds one block");
        frame[HEADER_LEN..].copy_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Applies [`advances_sequence`] to a wrapped command's reply.
    ///
    /// Every wrapped command routes its reply through here, so the rule has exactly one home.
    pub(crate) fn note_wrapped_reply(&mut self, has_body: bool, status: u32) {
        if advances_sequence(self.sequence_rule, has_body, status) {
            self.next_sequence = self.next_sequence.wrapping_add(1);
        }
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
            && self.client_nonce_len == other.client_nonce_len
            && self.device_nonce_len == other.device_nonce_len
            && self.host_nonce_len == other.host_nonce_len
            && self.key.0 == other.key.0
            && self.next_sequence == other.next_sequence
            && self.sequence_rule == other.sequence_rule
    }
}

impl Eq for Session {}

/// Which reading of the wrap-sequence rule the session applies.
///
/// The audited reference implementation (`bump_seq`) advances the counter whenever a wrapped
/// command's reply carries a body and the status is not `0x0F`, so a `0x85` "capture pending"
/// reply advances too. The alternative reading treats `0x85` as a refusal that leaves the counter
/// where it was. The two disagree only on that one reply.
///
/// **The hardware measurement is still pending.** Neither reading has been observed on this
/// sensor by this project; `cvctl cancel-then-verify` is the run that settles it. Until then the
/// driver ships [`SequenceRule::SHIPPED`], and switching the shipped reading is a one-line change
/// to that constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SequenceRule {
    /// A body-bearing reply advances unless the status is `0x0F`; `0x85` advances.
    #[default]
    Reference,
    /// A `0x85` "capture pending" reply keeps the sequence; every other body-bearing reply
    /// advances unless the status is `0x0F`.
    CapturePendingKeepsSequence,
}

impl SequenceRule {
    /// The reading this driver ships.
    ///
    /// This is the one line to change if `cvctl cancel-then-verify` shows the sensor keeping its
    /// counter across a `0x85` reply. The measurement has not been made yet.
    pub const SHIPPED: Self = Self::Reference;
}

/// Whether a wrapped command's reply advances the wrap sequence.
///
/// The audited reference's `bump_seq` advances when the sensor returned a body and the status was
/// not `0x0F`: a `0x85` "capture pending" reply therefore advances. The alternative reading of the
/// same exchange treats a capture-pending reply as a refusal that leaves the sequence alone.
///
/// **The hardware measurement is still pending.** This project has not observed either reading on
/// the sensor; the reference notes are the only source. `cvctl cancel-then-verify` is the run that
/// settles it, and switching the shipped reading is the one-line change to [`SequenceRule::SHIPPED`].
///
/// This is the only copy of the rule. Wrapped operations call it through
/// [`Session::note_wrapped_reply`], never inline.
fn advances_sequence(rule: SequenceRule, has_body: bool, status: u32) -> bool {
    if !has_body || status == proto::status::BAD_SEQUENCE {
        return false;
    }
    match rule {
        SequenceRule::Reference => true,
        SequenceRule::CapturePendingKeepsSequence => status != proto::status::CAPTURE_PENDING,
    }
}

/// Why a wrapped command could not be built. All variants are host-side programming errors: the
/// lengths come from the operation, not from the sensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// The plaintext cannot hold the TLV and its 32-byte token.
    PlaintextTooShort {
        plaintext_len: usize,
        tlv_len: usize,
    },
    /// The plaintext exceeds [`MAX_PLAINTEXT_LEN`].
    PlaintextTooLarge { plaintext_len: usize, max: usize },
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooShort {
                plaintext_len,
                tlv_len,
            } => write!(
                f,
                "wrapped plaintext is {plaintext_len} bytes, too short for {tlv_len} TLV bytes plus \
                 a {TOKEN_LEN}-byte token"
            ),
            Self::PlaintextTooLarge { plaintext_len, max } => write!(
                f,
                "wrapped plaintext is {plaintext_len} bytes, more than the {max} allowed"
            ),
        }
    }
}

impl std::error::Error for WrapError {}

/// Why a device-supplied wrapped reply could not be decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapError {
    /// The reply's frame header does not validate.
    Frame(FrameError),
    /// The reply's encoding is neither wrapped form: not `0x02` (host → sensor) nor `0x03`
    /// (sensor → host).
    UnexpectedEncoding(u8),
    /// A wrapped reply must carry at least one ciphertext block.
    EmptyCiphertext,
    /// The ciphertext is not a whole number of AES blocks.
    CiphertextNotAligned { got: usize },
    /// The ciphertext exceeds [`MAX_CIPHERTEXT_LEN`].
    CiphertextTooLarge { got: usize, max: usize },
    /// CBC decryption or PKCS#7 unpadding failed.
    Crypto(CryptoError),
}

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "malformed wrapped reply: {error}"),
            Self::UnexpectedEncoding(encoding) => {
                write!(
                    f,
                    "wrapped reply has encoding {encoding:#04x}, neither wrapped encoding (0x02 or \
                     0x03)"
                )
            }
            Self::EmptyCiphertext => f.write_str("wrapped reply carries no ciphertext"),
            Self::CiphertextNotAligned { got } => {
                write!(
                    f,
                    "ciphertext is {got} bytes, not a whole number of AES blocks"
                )
            }
            Self::CiphertextTooLarge { got, max } => {
                write!(f, "ciphertext is {got} bytes, more than the {max} allowed")
            }
            Self::Crypto(error) => write!(f, "wrapped reply did not decrypt: {error}"),
        }
    }
}

impl std::error::Error for UnwrapError {}

/// A wrapped reply after validation and decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedReply {
    /// The reply header. `status` is plaintext at header offset 20 even inside a wrapped frame.
    pub header: Header,
    /// The decrypted plaintext, with PKCS#7 padding removed. It still carries the leading TLV and
    /// the reply's trailing zero padding; replies have no token.
    pub plaintext: Vec<u8>,
}

/// Why an open attempt failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The sensor rejected the wrap sequence (`0x0F`); the command was built at the wrong counter.
    WrongSequence,
    /// The sensor answered with another non-zero status.
    SensorStatus(u32),
    /// The wrapped command's reply arrived without a body, so it carried no status to trust.
    MissingReply,
    /// The reply body is not a valid frame.
    MalformedReply(FrameError),
    /// The command could not be built.
    Build(WrapError),
    /// The transport failed before a reply arrived.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSequence => f.write_str(
                "sensor rejected the wrap sequence (status 0x0f): the command carried a stale or \
                 unexpected sequence",
            ),
            Self::SensorStatus(status) => {
                write!(f, "sensor rejected the open with status {status:#04x}")
            }
            Self::MissingReply => f.write_str("sensor answered the open without a body"),
            Self::MalformedReply(error) => write!(f, "malformed open reply: {error}"),
            Self::Build(error) => write!(f, "cannot build the wrapped open command: {error}"),
            Self::Transport(error) => write!(f, "transport failed: {error}"),
            Self::Cancelled => f.write_str("open cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event while opening the session"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for OpenError {}

type OpenOutcome = Result<Session, OpenError>;

#[derive(Debug)]
enum OpenState {
    NotStarted,
    WaitingReply,
    /// The handle is being released; the open's own error is held until the close reply.
    ReleasingHandle {
        error: OpenError,
    },
    Done,
}

/// The wrapped `0x02` open.
///
/// The operation owns the [`Session`] from the handshake. It sends the open command at the
/// session's next sequence (or at [`Self::at_sequence`], for the probe's deliberate mismatch), and
/// succeeds only on status zero. The open reply carries no field this driver reads, so, like the
/// audited reference, only its frame header is validated; the reply's status is the verdict.
/// Any failure after the handle is known sends the plain `0x04` close before finishing, so no
/// handle dangles across reboots; the close reply never replaces the open error.
pub struct OpenSession {
    session: Option<Session>,
    handle: u32,
    iv: [u8; crypto::BLOCK_LEN],
    sequence_override: Option<u32>,
    state: OpenState,
}

impl OpenSession {
    /// Builds the open for `session`, using `iv` for the wrapped frame. The probe draws the IV from
    /// the operating system.
    pub fn new(session: Session, iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            iv,
            sequence_override: None,
            state: OpenState::NotStarted,
        }
    }

    /// Sends `sequence` instead of the session's own next one.
    ///
    /// This exists so `cvctl open --bad-sequence` can make the sensor answer `0x0F` on hardware;
    /// the protocol rule itself is unchanged.
    pub fn at_sequence(mut self, sequence: u32) -> Self {
        self.sequence_override = Some(sequence);
        self
    }

    fn finish(&mut self, outcome: OpenOutcome) -> Action<OpenOutcome> {
        self.state = OpenState::Done;
        Action::Finish(outcome)
    }

    /// Drops the key material and releases a known handle before finishing with `error`.
    fn teardown(&mut self, error: OpenError) -> Action<OpenOutcome> {
        self.session = None;
        if self.handle == 0 {
            return self.finish(Err(error));
        }
        self.state = OpenState::ReleasingHandle { error };
        Action::Send(frame::build_close_handle(self.handle))
    }

    fn open_frame(&self, session: &Session) -> Result<Vec<u8>, WrapError> {
        let sequence = self.sequence_override.unwrap_or(session.next_sequence());
        session.wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            OPEN_PLAINTEXT_LEN,
            &self.iv,
            sequence,
        )
    }

    fn on_reply(&mut self, status: u32, body: Vec<u8>) -> Action<OpenOutcome> {
        // The one sequence rule applies to this reply before it is interpreted: a body advances
        // the counter unless the sensor said 0x0F, which includes the 0x85 capture-pending case.
        let has_body = !body.is_empty();
        if let Some(session) = self.session.as_mut() {
            session.note_wrapped_reply(has_body, status);
        }

        if status != proto::status::OK {
            return if status == proto::status::BAD_SEQUENCE {
                self.teardown(OpenError::WrongSequence)
            } else {
                self.teardown(OpenError::SensorStatus(status))
            };
        }
        if let Err(error) = frame::validate(&body) {
            return self.teardown(OpenError::MalformedReply(error));
        }
        match self.session.take() {
            Some(session) => self.finish(Ok(session)),
            None => self.finish(Err(OpenError::AlreadyFinished)),
        }
    }
}

impl Operation for OpenSession {
    type Output = OpenOutcome;

    fn start(&mut self) -> Action<OpenOutcome> {
        if !matches!(self.state, OpenState::NotStarted) {
            return self.finish(Err(OpenError::AlreadyFinished));
        }
        let built = match self.session.as_ref() {
            Some(session) => self.open_frame(session),
            None => return self.finish(Err(OpenError::AlreadyFinished)),
        };
        match built {
            Ok(frame) => {
                self.state = OpenState::WaitingReply;
                Action::Send(frame)
            }
            Err(error) => self.teardown(OpenError::Build(error)),
        }
    }

    fn step(&mut self, event: Event) -> Action<OpenOutcome> {
        match std::mem::replace(&mut self.state, OpenState::Done) {
            OpenState::NotStarted => self.finish(Err(OpenError::UnexpectedEvent)),
            OpenState::WaitingReply => match event {
                Event::Reply { status, body } => self.on_reply(status, body),
                Event::ReplyWithoutBody => {
                    if let Some(session) = self.session.as_mut() {
                        session.note_wrapped_reply(false, 0);
                    }
                    self.teardown(OpenError::MissingReply)
                }
                Event::Transport(error) => self.teardown(OpenError::Transport(error)),
                Event::Cancelled => self.teardown(OpenError::Cancelled),
                Event::Finger => self.teardown(OpenError::UnexpectedEvent),
            },
            OpenState::ReleasingHandle { error } => self.finish(Err(error)),
            OpenState::Done => self.finish(Err(OpenError::AlreadyFinished)),
        }
    }
}

/// Why a close reported a transport problem.
///
/// A close never fails because of the sensor: any reply, a body or no body, means the handle is
/// gone. Only the transport can fail, and even then the handle is treated as closed locally,
/// because no retry is safe or useful once the command was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseError {
    /// The command or its reply could not be transferred.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
}

impl fmt::Display for CloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(
                f,
                "closing the session failed in the transport: {error}; the handle is considered \
                 closed locally"
            ),
            Self::Cancelled => {
                f.write_str("closing the session was cancelled; the handle is considered closed")
            }
            Self::UnexpectedEvent => f.write_str(
                "unexpected event while closing the session; the handle is considered closed",
            ),
        }
    }
}

impl std::error::Error for CloseError {}

type CloseOutcome = Result<(), CloseError>;

#[derive(Debug)]
enum CloseState {
    NotStarted,
    WaitingReply,
    Done,
}

/// The plain `0x04` close.
///
/// It sends the close-handle frame (handle zero is already closed and sends nothing) and treats any
/// reply as success. Closing twice is harmless: a finished operation keeps returning `Ok(())`
/// instead of panicking.
pub struct CloseSession {
    handle: u32,
    state: CloseState,
}

impl CloseSession {
    /// Builds a close for a known handle. A zero handle is the protocol's "no session" value.
    pub fn new(handle: u32) -> Self {
        Self {
            handle,
            state: CloseState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: CloseOutcome) -> Action<CloseOutcome> {
        self.state = CloseState::Done;
        Action::Finish(outcome)
    }
}

impl Operation for CloseSession {
    type Output = CloseOutcome;

    fn start(&mut self) -> Action<CloseOutcome> {
        if !matches!(self.state, CloseState::NotStarted) {
            return self.finish(Ok(()));
        }
        if self.handle == 0 {
            return self.finish(Ok(()));
        }
        self.state = CloseState::WaitingReply;
        Action::Send(frame::build_close_handle(self.handle))
    }

    fn step(&mut self, event: Event) -> Action<CloseOutcome> {
        match std::mem::replace(&mut self.state, CloseState::Done) {
            CloseState::WaitingReply => match event {
                // The close is best effort: a reply of any status, with or without a body, says
                // the sensor has released the handle.
                Event::Reply { .. } | Event::ReplyWithoutBody => self.finish(Ok(())),
                Event::Transport(error) => self.finish(Err(CloseError::Transport(error))),
                Event::Cancelled => self.finish(Err(CloseError::Cancelled)),
                Event::Finger => self.finish(Err(CloseError::UnexpectedEvent)),
            },
            // Already closed: idempotent, and a `start`/`step` after the finish never panics.
            CloseState::NotStarted | CloseState::Done => self.finish(Ok(())),
        }
    }
}

/// Why a teardown reported a problem.
///
/// Teardown is best effort: both frames are attempted whatever the first one answered, and the
/// first problem is reported only after the close has had its turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownError {
    /// A teardown command or its reply could not be transferred.
    Transport(TransportError),
    /// The operation was cancelled; a command transfer never is, so this is unexpected.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
}

impl fmt::Display for TeardownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => {
                write!(f, "session teardown failed in the transport: {error}")
            }
            Self::Cancelled => f.write_str("session teardown was cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event during session teardown"),
        }
    }
}

impl std::error::Error for TeardownError {}

type TeardownOutcome = Result<(), TeardownError>;

#[derive(Debug)]
enum TeardownState {
    NotStarted,
    WaitingCancel,
    WaitingClose,
    Done,
}

/// Cancels a possibly-armed capture, then releases the session handle.
///
/// The cancel is the sessionless `0x68` (attr `0x44`, header handle zero), which clears a capture
/// left armed by an interrupted run even when the session is no longer usable; the close is the
/// plain `0x04` [`CloseSession`] sends. Any reply, with or without a body, counts as success for
/// that step, and a failure in the cancel never stops the close: teardown is best effort.
///
/// A zero handle is the protocol's "no session" value, so it sends nothing. A finished teardown is
/// idempotent: `start` and `step` keep returning `Ok(())` instead of panicking.
#[derive(Debug)]
pub struct Teardown {
    handle: u32,
    state: TeardownState,
    problem: Option<TeardownError>,
}

impl Teardown {
    /// Builds the teardown for a handle learned by the handshake.
    pub fn new(handle: u32) -> Self {
        Self {
            handle,
            state: TeardownState::NotStarted,
            problem: None,
        }
    }

    fn finish(&mut self, outcome: TeardownOutcome) -> Action<TeardownOutcome> {
        self.state = TeardownState::Done;
        Action::Finish(outcome)
    }

    /// Records the first non-reply event, which is the only way a teardown step can go wrong.
    fn note(&mut self, event: Event) {
        let problem = match event {
            Event::Reply { .. } | Event::ReplyWithoutBody => return,
            Event::Transport(error) => TeardownError::Transport(error),
            Event::Cancelled => TeardownError::Cancelled,
            Event::Finger => TeardownError::UnexpectedEvent,
        };
        if self.problem.is_none() {
            self.problem = Some(problem);
        }
    }
}

impl Operation for Teardown {
    type Output = TeardownOutcome;

    fn start(&mut self) -> Action<TeardownOutcome> {
        if !matches!(self.state, TeardownState::NotStarted) {
            return self.finish(Ok(()));
        }
        if self.handle == 0 {
            return self.finish(Ok(()));
        }
        self.state = TeardownState::WaitingCancel;
        Action::Send(frame::build_cancel_capture(self.handle))
    }

    fn step(&mut self, event: Event) -> Action<TeardownOutcome> {
        match std::mem::replace(&mut self.state, TeardownState::Done) {
            TeardownState::WaitingCancel => {
                self.note(event);
                // Deliberately irrespective of the cancel's outcome: the close must still happen.
                self.state = TeardownState::WaitingClose;
                Action::Send(frame::build_close_handle(self.handle))
            }
            TeardownState::WaitingClose => {
                self.note(event);
                let outcome = match self.problem.take() {
                    Some(problem) => Err(problem),
                    None => Ok(()),
                };
                self.finish(outcome)
            }
            TeardownState::NotStarted | TeardownState::Done => self.finish(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: u32 = 0x1122_3344;

    /// Independently computed from the protocol: SHA-256("CV secure session blob\0").
    const EXPECTED_MAC_KEY: &str =
        "25dd01727a9ebd451ccee66e87ad800cc7c8c01277f11de76b6e9ea745656ef9";
    /// HMAC-SHA-256 over header(44) || OPEN_TLV || u32le(0), keyed with EXPECTED_MAC_KEY.
    const EXPECTED_TOKEN: &str = "60c6595f0b287635c09ddb82ae1970fd3289bca47dd7dea24102ecddcd12975c";
    /// The same HMAC at sequence 1.
    const EXPECTED_TOKEN_SEQ_1: &str =
        "2bba408708a14eb1709d8a6fe3b4ce474f82d0b9ffb474b01fcb6335c3f67f9c";
    /// AES-128-CBC/PKCS#7 of OPEN_TLV || token || zeros under the fixed key and IV below,
    /// computed with OpenSSL from that plaintext.
    const EXPECTED_CIPHERTEXT: &str = "\
        b569af53382ede7d72e6f2a71c6c97cc\
        7cff61487ebcf116752d5e68471dc24d\
        f1b78326250c0bf1a4160b201b8305d8\
        5b9611fbed1936d2f1ed83d367a82939\
        8246f803ed4940ce24dbe2e0902fccd5\
        815e0354dee9b605e45002c99dbdf6ce";

    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        digits
            .chunks(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
                let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
                (high << 4) | low
            })
            .collect()
    }

    fn session_key() -> SessionKey {
        let mut bytes = [0u8; SESSION_KEY_LEN];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = index as u8;
        }
        SessionKey::new(bytes)
    }

    fn fixed_iv() -> [u8; crypto::BLOCK_LEN] {
        let mut iv = [0u8; crypto::BLOCK_LEN];
        for (index, byte) in iv.iter_mut().enumerate() {
            *byte = 0x10 + index as u8;
        }
        iv
    }

    fn session_at(sequence: u32) -> Session {
        Session::new(HANDLE, 20, 20, 20, session_key(), sequence)
    }

    fn open_frame(sequence: u32) -> Vec<u8> {
        session_at(0)
            .wrap(
                cmd::OPEN_SESSION,
                attr::SESSION,
                &OPEN_TLV,
                OPEN_PLAINTEXT_LEN,
                &fixed_iv(),
                sequence,
            )
            .expect("the open constants are valid")
    }

    fn open_reply(status: u32) -> Vec<u8> {
        frame::build_plain_reply(cmd::OPEN_SESSION, attr::SESSION, HANDLE, status, &[])
    }

    fn expect_send<T: fmt::Debug>(action: Action<T>) -> Vec<u8> {
        match action {
            Action::Send(frame) => frame,
            other => panic!("expected a send, got {other:?}"),
        }
    }

    fn expect_finish<T: fmt::Debug>(action: Action<T>) -> T {
        match action {
            Action::Finish(value) => value,
            other => panic!("expected a finish, got {other:?}"),
        }
    }

    fn le32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn the_mac_key_is_the_published_seed_hashed_once() {
        assert_eq!(MAC_SEED.len(), 23, "the seed's NUL is part of the constant");
        assert_eq!(mac_key().as_slice(), unhex(EXPECTED_MAC_KEY));
    }

    #[test]
    fn the_wrapped_open_matches_the_wire_layout() {
        let frame = open_frame(0);

        assert_eq!(frame.len(), 140);
        assert_eq!(le32(&frame, 0), 1, "magic");
        assert_eq!(le32(&frame, 4), 140, "total length");
        assert_eq!(&frame[8..10], &[0x02, 0x00], "open command");
        assert_eq!(frame[10], attr::SESSION, "attribute");
        assert_eq!(frame[11], Encoding::Wrapped as u8, "encoding");
        assert_eq!(le32(&frame, 12), 2, "kind");
        assert_eq!(le32(&frame, 16), HANDLE, "session handle");
        assert_eq!(le32(&frame, 20), 0, "status is zero on the wire");
        assert_eq!(
            &frame[IV_OFFSET..IV_OFFSET + 16],
            &fixed_iv(),
            "IV position"
        );
        assert_eq!(
            le32(&frame, frame::PARAM_LEN_OFFSET),
            OPEN_TLV.len() as u32,
            "declared parameter length is the TLV length"
        );
        assert_eq!(
            frame.len() - HEADER_LEN,
            96,
            "five plaintext blocks plus padding"
        );

        let header = frame::validate(&frame).expect("the frame validates");
        assert_eq!(header.handle, HANDLE);
        assert_eq!(header.cmd, cmd::OPEN_SESSION);
        assert_eq!(header.parameter_len(), 96, "ciphertext follows the header");
    }

    #[test]
    fn the_token_covers_header_tlv_and_sequence_and_the_ciphertext_matches_the_standard() {
        let frame = open_frame(0);

        assert_eq!(&frame[HEADER_LEN..], unhex(EXPECTED_CIPHERTEXT).as_slice());

        let plaintext =
            crypto::decrypt_cbc(session_key().as_bytes(), &fixed_iv(), &frame[HEADER_LEN..])
                .expect("the frame decrypts");
        assert_eq!(plaintext.len(), OPEN_PLAINTEXT_LEN);
        assert_eq!(&plaintext[..OPEN_TLV.len()], &OPEN_TLV);
        assert_eq!(
            &plaintext[OPEN_TLV.len()..OPEN_TLV.len() + TOKEN_LEN],
            unhex(EXPECTED_TOKEN).as_slice(),
            "token = HMAC-SHA-256(macKey, header(44) || TLV || u32le(seq))"
        );
        assert!(
            plaintext[OPEN_TLV.len() + TOKEN_LEN..]
                .iter()
                .all(|byte| *byte == 0),
            "the rest of the plaintext is zero padding"
        );

        let at_one = open_frame(1);
        let plaintext =
            crypto::decrypt_cbc(session_key().as_bytes(), &fixed_iv(), &at_one[HEADER_LEN..])
                .expect("the frame decrypts");
        assert_eq!(
            &plaintext[OPEN_TLV.len()..OPEN_TLV.len() + TOKEN_LEN],
            unhex(EXPECTED_TOKEN_SEQ_1).as_slice(),
            "the sequence is the last input to the token"
        );
        assert_ne!(
            &frame[HEADER_LEN..],
            &at_one[HEADER_LEN..],
            "sequence changes the ciphertext"
        );
    }

    #[test]
    fn impossible_plaintext_lengths_are_refused_without_panicking() {
        let too_narrow = session_at(0).wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            16,
            &fixed_iv(),
            0,
        );
        assert_eq!(
            too_narrow,
            Err(WrapError::PlaintextTooShort {
                plaintext_len: 16,
                tlv_len: OPEN_TLV.len(),
            })
        );

        let oversized = session_at(0).wrap(
            cmd::OPEN_SESSION,
            attr::SESSION,
            &OPEN_TLV,
            MAX_PLAINTEXT_LEN + 16,
            &fixed_iv(),
            0,
        );
        assert_eq!(
            oversized,
            Err(WrapError::PlaintextTooLarge {
                plaintext_len: MAX_PLAINTEXT_LEN + 16,
                max: MAX_PLAINTEXT_LEN,
            })
        );
    }

    #[test]
    fn a_partial_plaintext_block_is_padded_to_the_next_block() {
        let frame = session_at(0)
            .wrap(
                cmd::OPEN_SESSION,
                attr::SESSION,
                &OPEN_TLV,
                81,
                &fixed_iv(),
                0,
            )
            .expect("81 bytes holds the TLV and token");
        assert_eq!(
            frame.len(),
            HEADER_LEN + 96,
            "PKCS#7 pads 81 bytes to ((81 / 16) + 1) * 16 bytes"
        );

        let plaintext =
            crypto::decrypt_cbc(session_key().as_bytes(), &fixed_iv(), &frame[HEADER_LEN..])
                .expect("the frame decrypts");
        assert_eq!(plaintext.len(), 81);
        assert_eq!(&plaintext[..OPEN_TLV.len()], &OPEN_TLV);
    }

    #[test]
    fn a_valid_wrapped_reply_is_validated_and_decrypted() {
        let body = open_frame(0);
        let reply = session_key().unwrap(&body).expect("a valid wrapped frame");

        assert_eq!(reply.header.handle, HANDLE);
        assert_eq!(reply.header.status, 0);
        assert_eq!(reply.header.encoding, Encoding::Wrapped as u8);
        assert_eq!(reply.plaintext.len(), OPEN_PLAINTEXT_LEN);
        assert_eq!(&reply.plaintext[..OPEN_TLV.len()], &OPEN_TLV);
    }

    #[test]
    fn the_reply_status_at_offset_20_is_plaintext_even_inside_a_wrapped_frame() {
        let mut body = open_frame(0);
        body[20..24].copy_from_slice(&proto::status::BAD_SEQUENCE.to_le_bytes());

        let reply = session_key()
            .unwrap(&body)
            .expect("status is not encrypted");
        assert_eq!(reply.header.status, proto::status::BAD_SEQUENCE);
    }

    #[test]
    fn a_reply_with_the_reply_encoding_decrypts_like_one_with_the_command_encoding() {
        let as_command = open_frame(0);
        let mut as_reply = as_command.clone();
        as_reply[11] = Encoding::WrappedReply as u8;

        let command = session_key()
            .unwrap(&as_command)
            .expect("0x02 is a wrapped encoding");
        let reply = session_key()
            .unwrap(&as_reply)
            .expect("0x03 is a wrapped encoding");

        assert_eq!(reply.plaintext, command.plaintext);
        assert_eq!(reply.header.handle, command.header.handle);
        assert_eq!(reply.header.status, command.header.status);
        assert_eq!(command.header.encoding, Encoding::Wrapped as u8);
        assert_eq!(reply.header.encoding, Encoding::WrappedReply as u8);
    }

    #[test]
    fn unwrap_refuses_the_encodings_that_are_not_wrapped() {
        for encoding in [
            Encoding::Plain as u8,
            Encoding::CloseHandle as u8,
            0x01,
            0x05,
        ] {
            let mut body = open_frame(0);
            body[11] = encoding;

            assert_eq!(
                session_key().unwrap(&body),
                Err(UnwrapError::UnexpectedEncoding(encoding))
            );
        }
    }

    #[test]
    fn unwrap_refuses_empty_unaligned_and_oversized_ciphertext() {
        let empty = frame::build_wrapped(
            cmd::OPEN_SESSION,
            attr::SESSION,
            HANDLE,
            &fixed_iv(),
            0,
            &[],
        );
        assert_eq!(
            session_key().unwrap(&empty),
            Err(UnwrapError::EmptyCiphertext)
        );

        let unaligned = frame::build_wrapped(
            cmd::OPEN_SESSION,
            attr::SESSION,
            HANDLE,
            &fixed_iv(),
            0,
            &[0u8; 17],
        );
        assert_eq!(
            session_key().unwrap(&unaligned),
            Err(UnwrapError::CiphertextNotAligned { got: 17 })
        );

        let oversized = frame::build_wrapped(
            cmd::OPEN_SESSION,
            attr::SESSION,
            HANDLE,
            &fixed_iv(),
            0,
            &vec![0u8; MAX_CIPHERTEXT_LEN + 16],
        );
        assert_eq!(
            session_key().unwrap(&oversized),
            Err(UnwrapError::CiphertextTooLarge {
                got: MAX_CIPHERTEXT_LEN + 16,
                max: MAX_CIPHERTEXT_LEN,
            })
        );
    }

    #[test]
    fn unwrap_refuses_bad_padding_and_a_wrong_encoding() {
        // Encrypt a whole block of zeros: unpadding sees a zero pad byte and must refuse.
        let ciphertext = crypto::encrypt_cbc_raw(session_key().as_bytes(), &fixed_iv(), &[0u8; 16])
            .expect("whole block");
        let bad = frame::build_wrapped(
            cmd::OPEN_SESSION,
            attr::SESSION,
            HANDLE,
            &fixed_iv(),
            0,
            &ciphertext,
        );
        assert_eq!(
            session_key().unwrap(&bad),
            Err(UnwrapError::Crypto(CryptoError::BadPadding))
        );

        let plain = frame::build_plain_reply(cmd::OPEN_SESSION, attr::SESSION, HANDLE, 0, &[]);
        assert_eq!(
            session_key().unwrap(&plain),
            Err(UnwrapError::UnexpectedEncoding(Encoding::Plain as u8))
        );
    }

    #[test]
    fn unwrap_refuses_a_malformed_header() {
        assert!(matches!(
            session_key().unwrap(&[0u8; HEADER_LEN - 1]),
            Err(UnwrapError::Frame(FrameError::Short { .. }))
        ));

        let mut body = open_frame(0);
        body[0] = 9;
        assert_eq!(
            session_key().unwrap(&body),
            Err(UnwrapError::Frame(FrameError::BadMagic(9)))
        );
    }

    fn assert_sequence(
        rule: SequenceRule,
        starts_at: u32,
        has_body: bool,
        status: u32,
        expected: u32,
    ) {
        let mut session = session_at(starts_at).with_sequence_rule(rule);
        session.note_wrapped_reply(has_body, status);
        assert_eq!(session.next_sequence(), expected);
    }

    #[test]
    fn the_shipped_rule_is_the_reference_reading() {
        assert_eq!(SequenceRule::SHIPPED, SequenceRule::Reference);
        assert_eq!(SequenceRule::default(), SequenceRule::Reference);
    }

    #[test]
    fn a_body_advances_the_wrap_sequence_unless_the_status_is_bad_sequence() {
        for rule in [
            SequenceRule::Reference,
            SequenceRule::CapturePendingKeepsSequence,
        ] {
            assert_sequence(rule, 0, true, proto::status::OK, 1);
            assert_sequence(rule, 7, true, proto::status::BAD_SEQUENCE, 7);
            assert_sequence(rule, 3, true, 0x0c, 4);
        }
        // The audited `bump_seq` reading: capture pending still advanced the sensor's counter.
        assert_sequence(
            SequenceRule::Reference,
            3,
            true,
            proto::status::CAPTURE_PENDING,
            4,
        );
        // The alternative reading: a pending capture is a refusal and keeps the counter.
        assert_sequence(
            SequenceRule::CapturePendingKeepsSequence,
            3,
            true,
            proto::status::CAPTURE_PENDING,
            3,
        );
    }

    #[test]
    fn a_reply_without_a_body_never_advances_the_sequence() {
        for rule in [
            SequenceRule::Reference,
            SequenceRule::CapturePendingKeepsSequence,
        ] {
            assert_sequence(rule, 5, false, proto::status::OK, 5);
            assert_sequence(rule, 5, false, 0x85, 5);
        }
    }

    #[test]
    fn rewinding_after_a_cancel_puts_the_sequence_back_one() {
        let mut session = session_at(3);
        session.rewind_sequence();

        assert_eq!(
            session.next_sequence(),
            2,
            "the re-arm after a cancel carries the first arm's sequence"
        );
    }

    #[test]
    fn the_key_and_sequence_are_kept_out_of_debug() {
        let session = session_at(0);
        let text = format!("{session:?}");

        assert!(text.contains("SessionKey(<redacted>)"), "{text}");
        assert!(
            !text.contains("000102030405060708090a0b0c0d0e0f"),
            "raw key bytes must not appear: {text}"
        );
    }

    #[test]
    fn a_zero_status_opens_the_session_and_consumes_sequence_zero() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let sent = expect_send(operation.start());
        assert_eq!(sent, open_frame(0));

        let opened = expect_finish(operation.step(Event::Reply {
            status: 0,
            body: open_reply(0),
        }))
        .expect("status zero opens the session");

        assert_eq!(opened.handle, HANDLE);
        assert_eq!(opened.next_sequence(), 1, "0x02 consumed sequence zero");
    }

    #[test]
    fn a_deliberate_sequence_override_is_what_goes_on_the_wire() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv()).at_sequence(1);

        assert_eq!(expect_send(operation.start()), open_frame(1));
    }

    #[test]
    fn a_bad_sequence_is_distinct_and_closes_the_handle() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();

        let close = expect_send(operation.step(Event::Reply {
            status: proto::status::BAD_SEQUENCE,
            body: open_reply(proto::status::BAD_SEQUENCE),
        }));
        assert_eq!(close, frame::build_close_handle(HANDLE));

        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(OpenError::WrongSequence)
        );
    }

    #[test]
    fn another_non_zero_status_is_distinct_from_a_bad_sequence() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();

        let close = expect_send(operation.step(Event::Reply {
            status: 0x0c,
            body: open_reply(0x0c),
        }));
        assert_eq!(close, frame::build_close_handle(HANDLE));

        assert_eq!(
            expect_finish(operation.step(Event::Reply {
                status: 0,
                body: open_reply(0)
            })),
            Err(OpenError::SensorStatus(0x0c)),
            "the close reply cannot replace the open error"
        );
    }

    #[test]
    fn a_malformed_open_reply_closes_the_handle_and_is_distinct() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();
        let mut body = open_reply(0);
        body[0] = 9;

        let close = expect_send(operation.step(Event::Reply { status: 0, body }));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Disconnected))),
            Err(OpenError::MalformedReply(FrameError::BadMagic(9)))
        );
    }

    #[test]
    fn a_no_body_open_reply_is_a_failure_and_closes_the_handle() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();

        let close = expect_send(operation.step(Event::ReplyWithoutBody));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(OpenError::MissingReply)
        );
    }

    #[test]
    fn a_transport_failure_still_closes_the_handle() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();

        let close = expect_send(operation.step(Event::Transport(TransportError::Timeout)));
        assert_eq!(close, frame::build_close_handle(HANDLE));
        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Timeout))),
            Err(OpenError::Transport(TransportError::Timeout))
        );
    }

    #[test]
    fn cancellation_and_unexpected_events_close_the_handle() {
        for (event, expected) in [
            (Event::Cancelled, OpenError::Cancelled),
            (Event::Finger, OpenError::UnexpectedEvent),
        ] {
            let mut operation = OpenSession::new(session_at(0), fixed_iv());
            let _ = operation.start();
            let close = expect_send(operation.step(event.clone()));
            assert_eq!(close, frame::build_close_handle(HANDLE));
            assert_eq!(
                expect_finish(operation.step(Event::Cancelled)),
                Err(expected)
            );
        }
    }

    #[test]
    fn a_finished_open_is_inert() {
        let mut operation = OpenSession::new(session_at(0), fixed_iv());
        let _ = operation.start();
        let _ = operation.step(Event::Reply {
            status: 0,
            body: open_reply(0),
        });

        assert_eq!(
            expect_finish(operation.step(Event::Finger)),
            Err(OpenError::AlreadyFinished)
        );
        assert_eq!(
            expect_finish(operation.start()),
            Err(OpenError::AlreadyFinished)
        );
    }

    #[test]
    fn a_zero_handle_has_nothing_to_close() {
        let mut operation =
            OpenSession::new(Session::new(0, 20, 20, 20, session_key(), 0), fixed_iv());
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::Reply {
                status: proto::status::BAD_SEQUENCE,
                body: open_reply(proto::status::BAD_SEQUENCE),
            })),
            Err(OpenError::WrongSequence),
            "no close frame can be sent for handle zero"
        );
    }

    #[test]
    fn close_sends_the_documented_frame_and_accepts_a_body_reply() {
        let mut operation = CloseSession::new(HANDLE);
        let sent = expect_send(operation.start());
        assert_eq!(sent, frame::build_close_handle(HANDLE));
        assert_eq!(sent.len(), 56);

        assert_eq!(
            expect_finish(operation.step(Event::Reply {
                status: 0,
                body: open_reply(0),
            })),
            Ok(())
        );
    }

    #[test]
    fn close_accepts_a_reply_without_a_body_and_any_status() {
        for event in [
            Event::ReplyWithoutBody,
            Event::Reply {
                status: 0x0f,
                body: open_reply(0x0f),
            },
        ] {
            let mut operation = CloseSession::new(HANDLE);
            let _ = operation.start();
            assert_eq!(expect_finish(operation.step(event)), Ok(()));
        }
    }

    #[test]
    fn closing_twice_is_harmless() {
        let mut first = CloseSession::new(HANDLE);
        let _ = first.start();
        let _ = first.step(Event::ReplyWithoutBody);

        assert_eq!(expect_finish(first.step(Event::ReplyWithoutBody)), Ok(()));
        assert_eq!(expect_finish(first.start()), Ok(()));

        let mut second = CloseSession::new(HANDLE);
        let _ = second.start();
        assert_eq!(
            expect_finish(second.step(Event::ReplyWithoutBody)),
            Ok(()),
            "a second close for the same handle is still a harmless success"
        );
    }

    #[test]
    fn a_zero_handle_closes_without_sending() {
        let mut operation = CloseSession::new(0);
        assert_eq!(expect_finish(operation.start()), Ok(()));
        assert_eq!(expect_finish(operation.step(Event::Finger)), Ok(()));
    }

    #[test]
    fn a_close_transport_failure_is_reported_but_the_handle_is_locally_closed() {
        let mut operation = CloseSession::new(HANDLE);
        let _ = operation.start();

        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Disconnected))),
            Err(CloseError::Transport(TransportError::Disconnected))
        );
        assert_eq!(
            expect_finish(operation.step(Event::Cancelled)),
            Ok(()),
            "the finished close keeps reporting the handle as closed"
        );
    }

    #[test]
    fn teardown_cancels_the_capture_before_closing_the_handle() {
        let mut operation = Teardown::new(HANDLE);

        let cancel = expect_send(operation.start());
        assert_eq!(cancel, frame::build_cancel_capture(HANDLE));
        assert_eq!(cancel.len(), 56);
        assert_eq!(&cancel[8..10], &[0x68, 0x00], "0x68");
        assert_eq!(cancel[10], attr::CANCEL_SESSIONLESS);
        assert_eq!(le32(&cancel, 16), 0, "sessionless header");
        assert_eq!(le32(&cancel, frame::PARAM_LEN_OFFSET), 12);
        assert_eq!(
            le32(&cancel, HEADER_LEN + 8),
            HANDLE,
            "the handle is a parameter"
        );

        let close = expect_send(operation.step(Event::ReplyWithoutBody));
        assert_eq!(close, frame::build_close_handle(HANDLE));

        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Ok(())
        );
    }

    #[test]
    fn teardown_is_best_effort_and_keeps_the_first_problem() {
        let mut operation = Teardown::new(HANDLE);
        let _ = operation.start();

        let close = expect_send(operation.step(Event::Transport(TransportError::Disconnected)));
        assert_eq!(
            close,
            frame::build_close_handle(HANDLE),
            "a failed cancel still closes the handle"
        );
        assert_eq!(
            expect_finish(operation.step(Event::Transport(TransportError::Timeout))),
            Err(TeardownError::Transport(TransportError::Disconnected)),
            "the first problem is the one reported"
        );
    }

    #[test]
    fn teardown_is_idempotent_and_a_zero_handle_sends_nothing() {
        let mut finished = Teardown::new(HANDLE);
        let _ = finished.start();
        let _ = finished.step(Event::ReplyWithoutBody);
        let _ = finished.step(Event::ReplyWithoutBody);
        assert_eq!(expect_finish(finished.step(Event::Finger)), Ok(()));
        assert_eq!(expect_finish(finished.start()), Ok(()));

        let mut nothing = Teardown::new(0);
        assert_eq!(expect_finish(nothing.start()), Ok(()));
        assert_eq!(expect_finish(nothing.step(Event::Cancelled)), Ok(()));
    }

    #[test]
    fn an_unexpected_event_during_teardown_still_closes_and_is_reported() {
        let mut operation = Teardown::new(HANDLE);
        let _ = operation.start();

        assert_eq!(
            expect_send(operation.step(Event::Finger)),
            frame::build_close_handle(HANDLE)
        );
        assert_eq!(
            expect_finish(operation.step(Event::ReplyWithoutBody)),
            Err(TeardownError::UnexpectedEvent)
        );
    }
}

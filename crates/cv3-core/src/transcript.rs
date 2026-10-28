//! Versioned in-memory transcripts of one operation, and the transports that write and replay them.
//!
//! A transcript records the subcommand it belongs to and an ordered list of both directions: every
//! host frame the operation asked to send, and every device outcome the transport produced. The
//! format is deliberately small and dependency-free, because it is the probe's evidence that a
//! behaviour seen once on hardware still reproduces without it.
//!
//! # Format
//!
//! ```text
//! +0   8B  magic = "CV3REC\0\0"
//! +8   u16 version = 2
//! +10  u32 command-name length
//! +14  ... command name (UTF-8)
//! +    u32 record count
//! +    records, each a tag byte followed by its fields
//! +    u8 material marker: 0 = none, 1 = session material follows
//! +    if 1:
//! +        32B host secret scalar (big-endian P-256)
//! +        20B client nonce
//! +        20B host nonce
//! +        u32 IV count
//! +        IV count * 16B IVs, in the order the run used them
//! ```
//!
//! Record tags: `1` host frame (u32 length + bytes), `2` reply (u32 status, u32 length + body),
//! `3` reply without a body, `4` finger, `5` transport error (u8 kind; `3` carries a u32 length +
//! UTF-8 message), `6` cancellation. A parser checks every length against the bytes that remain,
//! so a truncated or corrupt file is a [`TranscriptError`] and never a panic.
//!
//! # Session material and replay matching
//!
//! A transcript with material marker `1` is **sensitive**: it carries the ephemeral host secret
//! and both nonces that derive the session key, plus the IVs of the run. It exists only so replay
//! can decrypt the recorded wrapped replies and rebuild the exact host frames. Such a file must
//! never be committed; the probe writes it only under `--record`, the README says so and
//! `.gitignore` keeps `*.cvrec` out of git. [`Transcript::is_sensitive`] reports the marker.
//!
//! With material, replay compares each requested frame byte for byte, so a changed payload,
//! sequence, IV or TLV is a [`Divergence::FrameBytes`] rather than a silent success. Without
//! material the host keypair, both nonces, the wrapped IVs and therefore the ciphertext are fresh
//! on every run, so a replay cannot compare frames byte for byte: it matches a requested frame on
//! **command, attribute and header handle** only. That catches a changed operation shape, a
//! reordered command or a different handle, but not a different payload under the same command,
//! attribute and handle. A mismatch, or a transcript that ends or has records left over, is a
//! [`Divergence`], which is reported as its own outcome rather than silently ignored.
//!
//! # Recordings
//!
//! A transcript is local evidence, not a committed fixture: it holds real host frames and device
//! replies from one session. Recordings must not be committed. Committed fixtures stay synthetic
//! and are built from the codec.

use std::fmt;

use zeroize::Zeroize;

use crate::crypto;
use crate::event::{Event, TransportError};
use crate::frame::{self, FrameError};
use crate::handshake::NONCE_LEN;
use crate::transport::Transport;

/// First eight bytes of a transcript.
pub const MAGIC: [u8; 8] = *b"CV3REC\0\0";
/// The only transcript version this build writes or reads.
pub const VERSION: u16 = 2;

const MATERIAL_NONE: u8 = 0;
const MATERIAL_SESSION: u8 = 1;

const RECORD_HOST_FRAME: u8 = 1;
const RECORD_REPLY: u8 = 2;
const RECORD_REPLY_WITHOUT_BODY: u8 = 3;
const RECORD_FINGER: u8 = 4;
const RECORD_TRANSPORT: u8 = 5;
const RECORD_CANCELLED: u8 = 6;

const TRANSPORT_TIMEOUT: u8 = 0;
const TRANSPORT_DISCONNECTED: u8 = 1;
const TRANSPORT_STALL: u8 = 2;
const TRANSPORT_OTHER: u8 = 3;

/// The ephemeral material a replay needs to rebuild one recorded session exactly.
///
/// The host secret and both nonces derive the same session key from the recorded `0x23` reply, and
/// the IVs are the ones each wrapped command used. This is sensitive material: the type redacts
/// itself from `Debug` and zeroes its bytes on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionMaterial {
    host_secret: [u8; 32],
    client_nonce: [u8; NONCE_LEN],
    host_nonce: [u8; NONCE_LEN],
    ivs: Vec<[u8; crypto::BLOCK_LEN]>,
}

impl SessionMaterial {
    /// Builds material from the values a recorded run used.
    ///
    /// `ivs` holds one IV per wrapped command, in the order the operation used them.
    pub fn new(
        host_secret: [u8; 32],
        client_nonce: [u8; NONCE_LEN],
        host_nonce: [u8; NONCE_LEN],
        ivs: Vec<[u8; crypto::BLOCK_LEN]>,
    ) -> Self {
        Self {
            host_secret,
            client_nonce,
            host_nonce,
            ivs,
        }
    }

    /// The ephemeral host secret scalar.
    pub fn host_secret(&self) -> &[u8; 32] {
        &self.host_secret
    }

    /// The `0x23` client nonce.
    pub fn client_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.client_nonce
    }

    /// The `0x24` host nonce.
    pub fn host_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.host_nonce
    }

    /// The wrapped-command IVs, in the order the run used them.
    pub fn ivs(&self) -> &[[u8; crypto::BLOCK_LEN]] {
        &self.ivs
    }
}

impl fmt::Debug for SessionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionMaterial(<redacted>)")
    }
}

impl Drop for SessionMaterial {
    fn drop(&mut self) {
        self.host_secret.zeroize();
        self.client_nonce.zeroize();
        self.host_nonce.zeroize();
        self.ivs.zeroize();
    }
}

/// One recorded direction in a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptRecord {
    /// A frame the operation asked to send.
    HostFrame(Vec<u8>),
    /// A device reply with the command status and body.
    Reply { status: u32, body: Vec<u8> },
    /// A device reply with no announced body.
    ReplyWithoutBody,
    /// The sensor reported a finger.
    Finger,
    /// The transport failed.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
}

impl TranscriptRecord {
    fn from_event(event: &Event) -> Self {
        match event {
            Event::Reply { status, body } => Self::Reply {
                status: *status,
                body: body.clone(),
            },
            Event::ReplyWithoutBody => Self::ReplyWithoutBody,
            Event::Finger => Self::Finger,
            Event::Transport(error) => Self::Transport(error.clone()),
            Event::Cancelled => Self::Cancelled,
        }
    }

    fn into_event(self) -> Option<Event> {
        match self {
            Self::HostFrame(_) => None,
            Self::Reply { status, body } => Some(Event::Reply { status, body }),
            Self::ReplyWithoutBody => Some(Event::ReplyWithoutBody),
            Self::Finger => Some(Event::Finger),
            Self::Transport(error) => Some(Event::Transport(error)),
            Self::Cancelled => Some(Event::Cancelled),
        }
    }
}

/// A versioned recording of one operation's two directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    command: String,
    records: Vec<TranscriptRecord>,
    material: Option<SessionMaterial>,
}

impl Transcript {
    /// Starts an empty transcript for the named subcommand (`handshake`, `open`, `close`, `verify`).
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            records: Vec::new(),
            material: None,
        }
    }

    /// The subcommand this recording belongs to.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The recorded records, in order.
    pub fn records(&self) -> &[TranscriptRecord] {
        &self.records
    }

    /// The session material a replay needs, when this recording carries it.
    pub fn material(&self) -> Option<&SessionMaterial> {
        self.material.as_ref()
    }

    /// Whether the transcript carries session material and must be treated as sensitive.
    pub fn is_sensitive(&self) -> bool {
        self.material.is_some()
    }

    /// Attaches the material a replay needs to rebuild the session exactly.
    ///
    /// The file becomes sensitive: it now carries the ephemeral host secret, both nonces and the
    /// IVs. Only `--record` uses this, and only for replay.
    pub fn set_material(&mut self, material: SessionMaterial) {
        self.material = Some(material);
    }

    /// Returns the transcript with material attached, for a builder-style call.
    pub fn with_material(mut self, material: SessionMaterial) -> Self {
        self.set_material(material);
        self
    }

    /// Appends one record.
    pub fn push(&mut self, record: TranscriptRecord) {
        self.records.push(record);
    }

    /// Serialises the transcript into the versioned byte format described in the module docs.
    ///
    /// Lengths are `u32`; a transcript built in memory cannot exceed them in practice.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());

        let name = self.command.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);

        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for record in &self.records {
            match record {
                TranscriptRecord::HostFrame(frame) => {
                    out.push(RECORD_HOST_FRAME);
                    put_bytes(&mut out, frame);
                }
                TranscriptRecord::Reply { status, body } => {
                    out.push(RECORD_REPLY);
                    out.extend_from_slice(&status.to_le_bytes());
                    put_bytes(&mut out, body);
                }
                TranscriptRecord::ReplyWithoutBody => out.push(RECORD_REPLY_WITHOUT_BODY),
                TranscriptRecord::Finger => out.push(RECORD_FINGER),
                TranscriptRecord::Transport(error) => {
                    out.push(RECORD_TRANSPORT);
                    put_transport_error(&mut out, error);
                }
                TranscriptRecord::Cancelled => out.push(RECORD_CANCELLED),
            }
        }

        match &self.material {
            None => out.push(MATERIAL_NONE),
            Some(material) => {
                out.push(MATERIAL_SESSION);
                out.extend_from_slice(material.host_secret());
                out.extend_from_slice(material.client_nonce());
                out.extend_from_slice(material.host_nonce());
                out.extend_from_slice(&(material.ivs().len() as u32).to_le_bytes());
                for iv in material.ivs() {
                    out.extend_from_slice(iv);
                }
            }
        }

        out
    }

    /// Parses the versioned byte format, rejecting anything it cannot trust.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TranscriptError> {
        let mut cursor = Cursor::new(bytes);

        let magic: [u8; 8] = cursor
            .take(8)
            .map_err(|_| TranscriptError::Truncated {
                at: 0,
                need: 8,
                got: bytes.len(),
            })?
            .try_into()
            .expect("take(8) returns eight bytes");
        if magic != MAGIC {
            return Err(TranscriptError::BadMagic(magic));
        }

        let version = cursor.u16()?;
        if version != VERSION {
            return Err(TranscriptError::UnknownVersion(version));
        }

        let name_len = cursor.u32()? as usize;
        let name = cursor.variable(name_len, "command name")?;
        let command = std::str::from_utf8(name)
            .map_err(|_| TranscriptError::CommandNameNotUtf8)?
            .to_owned();

        let count = cursor.u32()? as usize;
        if count > cursor.remaining() {
            return Err(TranscriptError::BadLength {
                field: "record count",
                value: count as u32,
                remaining: cursor.remaining(),
            });
        }

        let mut records = Vec::new();
        for _ in 0..count {
            let tag = cursor.u8()?;
            let record = match tag {
                RECORD_HOST_FRAME => {
                    TranscriptRecord::HostFrame(cursor.variable_bytes("host frame length")?)
                }
                RECORD_REPLY => {
                    let status = cursor.u32()?;
                    let body = cursor.variable_bytes("reply body length")?;
                    TranscriptRecord::Reply { status, body }
                }
                RECORD_REPLY_WITHOUT_BODY => TranscriptRecord::ReplyWithoutBody,
                RECORD_FINGER => TranscriptRecord::Finger,
                RECORD_TRANSPORT => TranscriptRecord::Transport(cursor.transport_error()?),
                RECORD_CANCELLED => TranscriptRecord::Cancelled,
                other => return Err(TranscriptError::UnknownRecord(other)),
            };
            records.push(record);
        }

        let material = match cursor.u8()? {
            MATERIAL_NONE => None,
            MATERIAL_SESSION => {
                let host_secret = cursor.array::<32>()?;
                let client_nonce = cursor.array::<NONCE_LEN>()?;
                let host_nonce = cursor.array::<NONCE_LEN>()?;
                let count = cursor.u32()? as usize;
                if count > cursor.remaining() / crypto::BLOCK_LEN {
                    return Err(TranscriptError::BadLength {
                        field: "session material IV count",
                        value: u32::try_from(count).unwrap_or(u32::MAX),
                        remaining: cursor.remaining(),
                    });
                }
                let mut ivs = Vec::with_capacity(count);
                for _ in 0..count {
                    ivs.push(cursor.array::<{ crypto::BLOCK_LEN }>()?);
                }
                Some(SessionMaterial::new(
                    host_secret,
                    client_nonce,
                    host_nonce,
                    ivs,
                ))
            }
            other => return Err(TranscriptError::UnknownMaterialMarker(other)),
        };

        let trailing = cursor.remaining();
        if trailing != 0 {
            return Err(TranscriptError::TrailingBytes { count: trailing });
        }

        Ok(Self {
            command,
            records,
            material,
        })
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_transport_error(out: &mut Vec<u8>, error: &TransportError) {
    match error {
        TransportError::Timeout => out.push(TRANSPORT_TIMEOUT),
        TransportError::Disconnected => out.push(TRANSPORT_DISCONNECTED),
        TransportError::Stall => out.push(TRANSPORT_STALL),
        TransportError::Other(message) => {
            out.push(TRANSPORT_OTHER);
            put_bytes(out, message.as_bytes());
        }
    }
}

/// Why a transcript could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// The file does not begin with [`MAGIC`].
    BadMagic([u8; 8]),
    /// The version is not [`VERSION`].
    UnknownVersion(u16),
    /// The bytes end before a fixed field or record tag.
    Truncated { at: usize, need: usize, got: usize },
    /// A declared length is larger than the bytes left.
    BadLength {
        field: &'static str,
        value: u32,
        remaining: usize,
    },
    /// The command name is not UTF-8.
    CommandNameNotUtf8,
    /// A transport-error message is not UTF-8.
    TransportMessageNotUtf8,
    /// A record tag is not one this version defines.
    UnknownRecord(u8),
    /// A transport-error kind is not one this version defines.
    UnknownTransport(u8),
    /// The trailing session-material marker is not one this version defines.
    UnknownMaterialMarker(u8),
    /// Bytes follow the last record.
    TrailingBytes { count: usize },
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(magic) => write!(f, "not a cv3 transcript (magic {magic:?})"),
            Self::UnknownVersion(version) => write!(
                f,
                "unsupported transcript version {version}; this build reads version {VERSION}"
            ),
            Self::Truncated { at, need, got } => write!(
                f,
                "transcript ends at byte {at}: needs {need} bytes, {got} remain"
            ),
            Self::BadLength {
                field,
                value,
                remaining,
            } => write!(
                f,
                "transcript declares {value} bytes for {field}, but only {remaining} remain"
            ),
            Self::CommandNameNotUtf8 => f.write_str("transcript command name is not UTF-8"),
            Self::TransportMessageNotUtf8 => {
                f.write_str("transcript transport-error message is not UTF-8")
            }
            Self::UnknownRecord(tag) => write!(f, "unknown transcript record tag {tag}"),
            Self::UnknownTransport(kind) => {
                write!(f, "unknown transcript transport-error kind {kind}")
            }
            Self::UnknownMaterialMarker(marker) => {
                write!(f, "unknown session-material marker {marker}")
            }
            Self::TrailingBytes { count } => {
                write!(f, "{count} bytes follow the last transcript record")
            }
        }
    }
}

impl std::error::Error for TranscriptError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TranscriptError> {
        let end = self.at.checked_add(len).ok_or(TranscriptError::Truncated {
            at: self.at,
            need: len,
            got: self.remaining(),
        })?;
        if end > self.bytes.len() {
            return Err(TranscriptError::Truncated {
                at: self.at,
                need: len,
                got: self.remaining(),
            });
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, TranscriptError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TranscriptError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("take(2)"),
        ))
    }

    fn u32(&mut self) -> Result<u32, TranscriptError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("take(4)"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TranscriptError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("take(N) returns exactly N bytes"))
    }

    /// Reads a length prefix and the bytes it names, refusing a length the buffer cannot hold.
    fn variable_bytes(&mut self, field: &'static str) -> Result<Vec<u8>, TranscriptError> {
        let len = self.u32()? as usize;
        Ok(self.variable(len, field)?.to_vec())
    }

    fn variable(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], TranscriptError> {
        if len > self.remaining() {
            return Err(TranscriptError::BadLength {
                field,
                value: u32::try_from(len).unwrap_or(u32::MAX),
                remaining: self.remaining(),
            });
        }
        self.take(len)
    }

    fn transport_error(&mut self) -> Result<TransportError, TranscriptError> {
        match self.u8()? {
            TRANSPORT_TIMEOUT => Ok(TransportError::Timeout),
            TRANSPORT_DISCONNECTED => Ok(TransportError::Disconnected),
            TRANSPORT_STALL => Ok(TransportError::Stall),
            TRANSPORT_OTHER => {
                let bytes = self.variable_bytes("transport-error message")?;
                String::from_utf8(bytes)
                    .map(TransportError::Other)
                    .map_err(|_| TranscriptError::TransportMessageNotUtf8)
            }
            other => Err(TranscriptError::UnknownTransport(other)),
        }
    }
}

/// Wraps a transport and records both directions as they happen.
#[derive(Debug)]
pub struct RecordingTransport<T> {
    inner: T,
    command: String,
    records: Vec<TranscriptRecord>,
}

impl<T: Transport> RecordingTransport<T> {
    /// Records the operation named `command` running over `inner`.
    pub fn new(inner: T, command: impl Into<String>) -> Self {
        Self {
            inner,
            command: command.into(),
            records: Vec::new(),
        }
    }

    /// The records captured so far.
    pub fn records(&self) -> &[TranscriptRecord] {
        &self.records
    }

    /// A copy of the transcript captured so far.
    pub fn transcript(&self) -> Transcript {
        Transcript {
            command: self.command.clone(),
            records: self.records.clone(),
            material: None,
        }
    }

    /// Consumes the recording transport and returns its transcript.
    pub fn into_transcript(self) -> Transcript {
        Transcript {
            command: self.command,
            records: self.records,
            material: None,
        }
    }
}

impl<T: Transport> Transport for RecordingTransport<T> {
    fn command(&mut self, frame: &[u8]) -> Event {
        self.records
            .push(TranscriptRecord::HostFrame(frame.to_vec()));
        let event = self.inner.command(frame);
        self.records.push(TranscriptRecord::from_event(&event));
        event
    }

    fn wait_finger(&mut self) -> Event {
        let event = self.inner.wait_finger();
        self.records.push(TranscriptRecord::from_event(&event));
        event
    }
}

/// The parts of a frame replay compares: command, attribute and header handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameKey {
    pub cmd: u16,
    pub attr: u8,
    pub handle: u32,
}

impl FrameKey {
    /// Reads the matching key from a frame. A frame too short or mis-magicked has no key.
    pub fn of(frame: &[u8]) -> Result<Self, FrameError> {
        let header = frame::Header::parse(frame)?;
        Ok(Self {
            cmd: header.cmd,
            attr: header.attr,
            handle: header.handle,
        })
    }
}

impl fmt::Display for FrameKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "command {:#06x}, attribute {:#04x}, handle {:#010x}",
            self.cmd, self.attr, self.handle
        )
    }
}

/// A replay that stopped matching the recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The operation asked to send a frame that is not even a frame.
    UnreadableRequest(FrameError),
    /// The operation asked for a different command, attribute or handle.
    CommandMismatch { expected: FrameKey, got: FrameKey },
    /// With session material recorded, the whole frame must match. This reports the first byte
    /// that differs, or the shorter length when one frame is a prefix of the other.
    FrameBytes {
        at: usize,
        expected_len: usize,
        got_len: usize,
    },
    /// The next record was not the host frame the operation was about to send.
    ExpectedHostFrame,
    /// The transcript ended before the operation asked for its next command.
    MissingHostFrame,
    /// The transcript ended without an outcome for the last host frame.
    MissingOutcome,
    /// A host frame appeared where a device outcome was expected.
    UnexpectedHostFrame,
    /// A reply appeared where only a finger, error or cancellation belongs.
    UnexpectedOutcome,
    /// The operation finished with records left in the transcript.
    UnconsumedRecords { count: usize },
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableRequest(error) => {
                write!(f, "the operation asked to send a malformed frame: {error}")
            }
            Self::CommandMismatch { expected, got } => write!(
                f,
                "the operation sent {got}, but the transcript recorded {expected}"
            ),
            Self::FrameBytes {
                at,
                expected_len,
                got_len,
            } => write!(
                f,
                "the operation's frame differs from the recording at byte {at} \
                 ({got_len} bytes sent, {expected_len} recorded)"
            ),
            Self::ExpectedHostFrame => {
                f.write_str("the transcript expected a host frame but found a device outcome")
            }
            Self::MissingHostFrame => {
                f.write_str("the transcript ended before the operation's next command")
            }
            Self::MissingOutcome => {
                f.write_str("the transcript ended without an outcome for the last command")
            }
            Self::UnexpectedHostFrame => {
                f.write_str("the transcript expected a device outcome but found a host frame")
            }
            Self::UnexpectedOutcome => {
                f.write_str("the transcript expected a finger, error or cancellation")
            }
            Self::UnconsumedRecords { count } => {
                write!(
                    f,
                    "the operation finished with {count} transcript records left"
                )
            }
        }
    }
}

impl std::error::Error for Divergence {}

/// Replays a recorded operation, feeding its device outcomes to a fresh operation.
///
/// See the module docs for the command/attribute/handle matching rule. A mismatch sets a
/// [`Divergence`] and returns a transport error to the operation; the operation then unwinds as
/// it would for any transport failure, and [`Self::finish`] reports the divergence to the caller.
#[derive(Debug)]
pub struct ReplayTransport {
    transcript: Transcript,
    next: usize,
    sent: Vec<Vec<u8>>,
    divergence: Option<Divergence>,
    exact: bool,
}

impl ReplayTransport {
    /// Replays `transcript`.
    pub fn new(transcript: Transcript) -> Self {
        let exact = transcript.material().is_some();
        Self {
            transcript,
            next: 0,
            sent: Vec::new(),
            divergence: None,
            exact,
        }
    }

    /// The subcommand the transcript belongs to.
    pub fn command_name(&self) -> &str {
        self.transcript.command()
    }

    /// Every frame the replayed operation asked to send, including any that diverged.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// The first divergence, if replay stopped matching the recording.
    pub fn divergence(&self) -> Option<&Divergence> {
        self.divergence.as_ref()
    }

    /// How many transcript records have not been consumed.
    pub fn remaining(&self) -> usize {
        self.transcript.records.len().saturating_sub(self.next)
    }

    /// Checks that the operation consumed the whole transcript and never diverged.
    ///
    /// Call this after the operation finishes. Leftover records are a divergence too: a shorter
    /// operation than the recording is a changed behaviour, not a successful replay.
    pub fn finish(&mut self) -> Result<(), Divergence> {
        if let Some(divergence) = &self.divergence {
            return Err(divergence.clone());
        }
        let count = self.remaining();
        if count != 0 {
            let divergence = Divergence::UnconsumedRecords { count };
            self.divergence = Some(divergence.clone());
            return Err(divergence);
        }
        Ok(())
    }

    fn diverge(&mut self, divergence: Divergence) -> Event {
        let message = divergence.to_string();
        self.divergence = Some(divergence);
        Event::Transport(TransportError::Other(format!("replay diverged: {message}")))
    }

    fn diverged(&mut self) -> Event {
        match &self.divergence {
            Some(divergence) => {
                let message = divergence.to_string();
                Event::Transport(TransportError::Other(format!("replay diverged: {message}")))
            }
            None => self.diverge(Divergence::MissingHostFrame),
        }
    }

    fn outcome(&mut self) -> Event {
        let Some(record) = self.transcript.records.get(self.next).cloned() else {
            return self.diverge(Divergence::MissingOutcome);
        };
        match record {
            TranscriptRecord::HostFrame(_) => self.diverge(Divergence::UnexpectedHostFrame),
            other => {
                self.next += 1;
                other.into_event().expect("checked not a host frame")
            }
        }
    }
}

impl Transport for ReplayTransport {
    fn command(&mut self, frame: &[u8]) -> Event {
        self.sent.push(frame.to_vec());
        if self.divergence.is_some() {
            return self.diverged();
        }

        let got = match FrameKey::of(frame) {
            Ok(key) => key,
            Err(error) => return self.diverge(Divergence::UnreadableRequest(error)),
        };

        let Some(record) = self.transcript.records.get(self.next).cloned() else {
            return self.diverge(Divergence::MissingHostFrame);
        };
        let recorded = match record {
            TranscriptRecord::HostFrame(recorded) => recorded,
            _ => return self.diverge(Divergence::ExpectedHostFrame),
        };
        if self.exact && recorded != frame {
            let at = recorded
                .iter()
                .zip(frame)
                .position(|(expected, got)| expected != got)
                .unwrap_or_else(|| recorded.len().min(frame.len()));
            return self.diverge(Divergence::FrameBytes {
                at,
                expected_len: recorded.len(),
                got_len: frame.len(),
            });
        }
        let expected = match FrameKey::of(&recorded) {
            Ok(key) => key,
            Err(_) => return self.diverge(Divergence::ExpectedHostFrame),
        };
        if !self.exact && got != expected {
            return self.diverge(Divergence::CommandMismatch { expected, got });
        }

        self.next += 1;
        self.outcome()
    }

    fn wait_finger(&mut self) -> Event {
        if self.divergence.is_some() {
            return self.diverged();
        }
        let Some(record) = self.transcript.records.get(self.next).cloned() else {
            return self.diverge(Divergence::MissingOutcome);
        };
        match record {
            TranscriptRecord::Finger
            | TranscriptRecord::Transport(_)
            | TranscriptRecord::Cancelled => {
                self.next += 1;
                record.into_event().expect("a device outcome")
            }
            _ => self.diverge(Divergence::UnexpectedOutcome),
        }
    }
}

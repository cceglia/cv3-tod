//! The wrapped `0x2F` template-inventory query, and a best-effort TLV scan of its reply.
//!
//! ```text
//! host → sensor  0x2F wrapped, attr 0x42   TLV 56 bytes, plaintext 88 bytes
//!                                       (0,4,handle) (0,4,0x48) (0,4,0x53e2) (0,4,0) (2,0)
//! sensor → host  wrapped reply             format not decoded: the reference only dumps it
//! ```
//!
//! The reference implementation sends this query after a commit to ask whether a template is now
//! stored, but it never interprets the reply. Ticket 16 owns the decoding; this module performs
//! the first step, which is to report the two lengths and the plaintext exactly as the sensor sent
//! it, plus a best-effort entry scan. Nothing here assumes the reply is a list of templates.
//!
//! [`scan_tlv`] is a pure function, deliberately separate from the operation: it walks the
//! decrypted plaintext four bytes at a time, reading a little-endian `u32 tag`, `u32 length` and
//! the declared value. It never indexes past the buffer and never panics on device bytes: a
//! declared value longer than what remains is reported as truncated, and trailing bytes too short
//! for a header are counted rather than decoded.
//!
//! [`Inventory`] follows the same lifecycle as the other wrapped operations: it owns the
//! [`Session`], sends the query at the session's next wrap sequence, applies the one sequence rule
//! to the reply, and returns the still-open session on success. Every failure runs the sessionless
//! `0x68` cancel and then the `0x04` close before the original error is returned; a teardown
//! failure never replaces that error.

use std::fmt;

use crate::crypto;
use crate::event::{Action, Event, TransportError};
use crate::operation::Operation;
use crate::proto::{self, attr, cmd};
use crate::session::{Session, Teardown, UnwrapError, WrapError};

/// Length of the `0x2F` parameter block: four `(tag, 4, value)` entries and `(2, 0)`.
pub const INVENTORY_TLV_LEN: usize = 56;
/// Plaintext length the reference sends with `0x2F`: the TLV, the 32-byte token, zero padding.
pub const INVENTORY_PLAINTEXT_LEN: usize = 88;

// The reply scanner is shared with the verify and commit diagnostics. It is re-exported here so
// the ticket-16 paths that already depend on `inventory::scan_tlv` keep working unchanged.
pub use crate::tlv::{TLV_ALIGNMENT, TLV_HEADER_LEN, TlvEntry, TlvScan, scan_tlv};

/// The 56-byte `0x2F` parameter block:
/// `(0,4,handle) (0,4,0x48) (0,4,0x53e2) (0,4,0) (2,0)`.
pub fn inventory_tlv(handle: u32) -> [u8; INVENTORY_TLV_LEN] {
    let mut tlv = [0u8; INVENTORY_TLV_LEN];
    let entries: [(usize, u32, u32); 4] =
        [(0, 0, handle), (12, 0, 0x48), (24, 0, 0x53e2), (36, 0, 0)];
    for (at, tag, value) in entries {
        tlv[at..at + 4].copy_from_slice(&tag.to_le_bytes());
        tlv[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes());
        tlv[at + 8..at + 12].copy_from_slice(&value.to_le_bytes());
    }
    tlv[48..52].copy_from_slice(&2u32.to_le_bytes());
    tlv[52..56].copy_from_slice(&0u32.to_le_bytes());
    tlv
}

/// A decoded `0x2F` reply: both lengths, the full plaintext, and the still-open session.
#[derive(Debug, PartialEq, Eq)]
pub struct InventoryReply {
    /// The raw wrapped reply body length, header included.
    pub reply_len: usize,
    /// The decrypted plaintext, exactly as it came out of CBC, padding removed.
    pub plaintext: Vec<u8>,
    /// The session, still open, at the sequence the reply left it at.
    pub session: Session,
}

/// Why the inventory query did not produce a reply.
///
/// Every variant is distinct on purpose: a hardware run can tell a refusal, a bodyless reply, a
/// plaintext too short to hold even one TLV header, an undecryptable body, a transport failure
/// and a cancellation without reading the message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    /// The sensor rejected the wrap sequence (`0x0F`).
    WrongSequence,
    /// The sensor answered `0x2F` with another non-zero status.
    ///
    /// The reply length and, when the body decrypted, the plaintext are kept so a hardware run can
    /// report what a refusal such as `0x0E` carried.
    SensorStatus {
        /// The status word the sensor returned.
        status: u32,
        /// The raw wrapped reply body length, header included (`0` for a body-less reply).
        reply_len: usize,
        /// The decrypted plaintext, when the body was a valid wrapped frame that decrypted.
        plaintext: Option<Vec<u8>>,
    },
    /// The command completed without an announced body.
    MissingReply,
    /// The reply decrypted, but it is shorter than one eight-byte TLV header.
    ShortReply {
        /// The decrypted plaintext length.
        plaintext_len: usize,
        /// The raw wrapped reply body length, header included.
        reply_len: usize,
    },
    /// The reply body could not be validated or decrypted.
    MalformedReply(UnwrapError),
    /// The wrapped command could not be built (a host-side programming error).
    Build(WrapError),
    /// The transport failed.
    Transport(TransportError),
    /// The operation was cancelled.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSequence => f.write_str(
                "sensor rejected the wrap sequence (status 0x0f) on the 0x2f inventory query: the \
                 command carried a stale or unexpected sequence",
            ),
            Self::SensorStatus {
                status,
                reply_len,
                plaintext,
            } => {
                write!(
                    f,
                    "sensor rejected the 0x2f inventory query with status {status:#04x} (raw reply \
                     {reply_len} bytes)"
                )?;
                match plaintext {
                    Some(bytes) => write!(f, "; decrypted plaintext {} bytes", bytes.len()),
                    None if *reply_len == 0 => f.write_str("; the reply carried no body"),
                    None => f.write_str("; the body did not decrypt"),
                }
            }
            Self::MissingReply => {
                f.write_str("sensor answered the 0x2f inventory query without a body")
            }
            Self::ShortReply {
                plaintext_len,
                reply_len,
            } => write!(
                f,
                "the 0x2f reply decrypted to {plaintext_len} bytes, too short for a {TLV_HEADER_LEN}\
                 -byte TLV header (reply was {reply_len} bytes); there is nothing to decode"
            ),
            Self::MalformedReply(error) => write!(f, "malformed 0x2f inventory reply: {error}"),
            Self::Build(error) => {
                write!(
                    f,
                    "cannot build the wrapped 0x2f inventory command: {error}"
                )
            }
            Self::Transport(error) => write!(
                f,
                "transport failed during the 0x2f inventory query: {error}"
            ),
            Self::Cancelled => f.write_str("inventory query cancelled"),
            Self::UnexpectedEvent => {
                f.write_str("unexpected event while waiting for the inventory reply")
            }
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for InventoryError {}

type InventoryOutcome = Result<InventoryReply, InventoryError>;

#[derive(Debug)]
enum InventoryState {
    NotStarted,
    WaitingReply,
    /// The original error is held until the best-effort teardown has run.
    TearingDown {
        original: InventoryError,
        teardown: Teardown,
    },
    Done,
}

/// The wrapped `0x2F` inventory query.
///
/// The operation owns the [`Session`] it was built with and returns it on success. `iv` is the CBC
/// IV for this one request; the caller draws it from the operating system, because the core
/// generates no randomness.
pub struct Inventory {
    session: Option<Session>,
    handle: u32,
    iv: [u8; crypto::BLOCK_LEN],
    state: InventoryState,
}

impl Inventory {
    /// Builds the query for a live session.
    pub fn new(session: Session, iv: [u8; crypto::BLOCK_LEN]) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            iv,
            state: InventoryState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: InventoryOutcome) -> Action<InventoryOutcome> {
        self.state = InventoryState::Done;
        Action::Finish(outcome)
    }

    /// Drops the session and starts the cancel-then-close teardown, preserving `error`.
    fn begin_teardown(&mut self, error: InventoryError) -> Action<InventoryOutcome> {
        self.session = None;
        let mut teardown = Teardown::new(self.handle);
        match teardown.start() {
            Action::Send(frame) => {
                self.state = InventoryState::TearingDown {
                    original: error,
                    teardown,
                };
                Action::Send(frame)
            }
            // A zero handle has nothing to tear down; any other action cannot come from Teardown.
            _ => self.finish(Err(error)),
        }
    }

    fn query_frame(&self, session: &Session) -> Result<Vec<u8>, WrapError> {
        session.wrap(
            cmd::INVENTORY,
            attr::INVENTORY,
            &inventory_tlv(session.handle),
            INVENTORY_PLAINTEXT_LEN,
            &self.iv,
            session.next_sequence(),
        )
    }

    fn on_reply(&mut self, status: u32, body: Vec<u8>) -> Action<InventoryOutcome> {
        // The one sequence predicate applies before the reply is interpreted: a body advances the
        // counter unless the sensor said 0x0F.
        let has_body = !body.is_empty();
        if let Some(session) = self.session.as_mut() {
            session.note_wrapped_reply(has_body, status);
        }

        if status == proto::status::BAD_SEQUENCE {
            return self.begin_teardown(InventoryError::WrongSequence);
        }
        if status != proto::status::OK {
            // A refusal can still carry a body; keep it for the hardware diagnostic instead of
            // discarding it with the status.
            let reply_len = body.len();
            let plaintext = self
                .session
                .as_ref()
                .and_then(|session| session.key().unwrap(&body).ok())
                .map(|reply| reply.plaintext);
            return self.begin_teardown(InventoryError::SensorStatus {
                status,
                reply_len,
                plaintext,
            });
        }
        if body.is_empty() {
            return self.begin_teardown(InventoryError::MissingReply);
        }

        let Some(session) = self.session.as_ref() else {
            return self.finish(Err(InventoryError::AlreadyFinished));
        };
        let reply = match session.key().unwrap(&body) {
            Ok(reply) => reply,
            Err(error) => return self.begin_teardown(InventoryError::MalformedReply(error)),
        };
        let reply_len = body.len();
        let plaintext_len = reply.plaintext.len();
        if plaintext_len < TLV_HEADER_LEN {
            return self.begin_teardown(InventoryError::ShortReply {
                plaintext_len,
                reply_len,
            });
        }

        match self.session.take() {
            Some(session) => self.finish(Ok(InventoryReply {
                reply_len,
                plaintext: reply.plaintext,
                session,
            })),
            None => self.finish(Err(InventoryError::AlreadyFinished)),
        }
    }
}

impl Operation for Inventory {
    type Output = InventoryOutcome;

    fn start(&mut self) -> Action<InventoryOutcome> {
        if !matches!(self.state, InventoryState::NotStarted) {
            return self.finish(Err(InventoryError::AlreadyFinished));
        }
        let built = match self.session.as_ref() {
            Some(session) => self.query_frame(session),
            None => return self.finish(Err(InventoryError::AlreadyFinished)),
        };
        match built {
            Ok(frame) => {
                self.state = InventoryState::WaitingReply;
                Action::Send(frame)
            }
            Err(error) => self.begin_teardown(InventoryError::Build(error)),
        }
    }

    fn step(&mut self, event: Event) -> Action<InventoryOutcome> {
        match std::mem::replace(&mut self.state, InventoryState::Done) {
            InventoryState::NotStarted => self.finish(Err(InventoryError::UnexpectedEvent)),
            InventoryState::WaitingReply => match event {
                Event::Reply { status, body } => self.on_reply(status, body),
                Event::ReplyWithoutBody => {
                    if let Some(session) = self.session.as_mut() {
                        session.note_wrapped_reply(false, 0);
                    }
                    self.begin_teardown(InventoryError::MissingReply)
                }
                Event::Transport(error) => self.begin_teardown(InventoryError::Transport(error)),
                Event::Cancelled => self.begin_teardown(InventoryError::Cancelled),
                Event::Finger => self.begin_teardown(InventoryError::UnexpectedEvent),
            },
            InventoryState::TearingDown {
                original,
                mut teardown,
            } => match teardown.step(event) {
                Action::Send(frame) => {
                    self.state = InventoryState::TearingDown { original, teardown };
                    Action::Send(frame)
                }
                // Teardown never waits; anything but another send is its end.
                _ => self.finish(Err(original)),
            },
            InventoryState::Done => self.finish(Err(InventoryError::AlreadyFinished)),
        }
    }
}

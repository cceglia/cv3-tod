//! Cancelling an armed capture while the secure session stays open.
//!
//! ```text
//! host → sensor  0x68 plain, attr 0x40   header handle = session handle
//!                                        TLV 12: (0,4,handle), declared length 12, total 56
//! sensor → host  any reply               with or without a body
//! ```
//!
//! This is the **mid-session** cancel: the header carries the live session handle, unlike the
//! sessionless cancel (attr `0x44`, header handle zero) that a teardown sends when the session is
//! being abandoned. Being plain, it does not advance the wrap sequence, so the next wrapped
//! command still carries the number the last wrapped reply left behind.
//!
//! The operation consumes the reply and returns the still-open [`Session`]. A non-zero status or
//! a transport failure is a failure: the source of truth in the SPEC is that any failure cancels a
//! pending capture and closes the handle before the error is reported, so the operation runs the
//! same sessionless `0x68` + `0x04` teardown as the other operations. A teardown failure never
//! replaces the original error.

use std::fmt;

use crate::event::{Action, Event, TransportError};
use crate::frame;
use crate::operation::Operation;
use crate::proto;
use crate::session::{Session, Teardown};

/// Why a mid-session cancel did not leave the session usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    /// The sensor answered the plain `0x68` with a non-zero status.
    SensorStatus(u32),
    /// The cancel or its reply could not be transferred.
    Transport(TransportError),
    /// The operation was cancelled. A command transfer never is, so this is defensive.
    Cancelled,
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for CancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SensorStatus(status) => {
                write!(
                    f,
                    "sensor rejected the mid-session 0x68 cancel with status {status:#04x}"
                )
            }
            Self::Transport(error) => {
                write!(
                    f,
                    "transport failed during the mid-session 0x68 cancel: {error}"
                )
            }
            Self::Cancelled => f.write_str("the mid-session cancel was cancelled"),
            Self::UnexpectedEvent => f.write_str("unexpected event during the mid-session cancel"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for CancelError {}

type CancelOutcome = Result<Session, CancelError>;

#[derive(Debug)]
enum CancelState {
    NotStarted,
    WaitingReply,
    /// The original error is held until the best-effort teardown has run.
    TearingDown {
        original: CancelError,
        teardown: Teardown,
    },
    Done,
}

/// The plain, session-scoped `0x68` cancel.
///
/// It owns the [`Session`] it was built with and returns it unchanged on success, so the caller can
/// carry on with the same handle and wrap sequence.
pub struct CancelCapture {
    session: Option<Session>,
    handle: u32,
    state: CancelState,
}

impl CancelCapture {
    /// Builds the cancel for a live session.
    pub fn new(session: Session) -> Self {
        Self {
            handle: session.handle,
            session: Some(session),
            state: CancelState::NotStarted,
        }
    }

    fn finish(&mut self, outcome: CancelOutcome) -> Action<CancelOutcome> {
        self.state = CancelState::Done;
        Action::Finish(outcome)
    }

    /// Drops the session and starts the cancel-then-close teardown, preserving `error`.
    fn begin_teardown(&mut self, error: CancelError) -> Action<CancelOutcome> {
        self.session = None;
        let mut teardown = Teardown::new(self.handle);
        match teardown.start() {
            Action::Send(frame) => {
                self.state = CancelState::TearingDown {
                    original: error,
                    teardown,
                };
                Action::Send(frame)
            }
            // A zero handle has nothing to tear down; any other action cannot come from Teardown.
            _ => self.finish(Err(error)),
        }
    }

    fn succeed(&mut self) -> Action<CancelOutcome> {
        match self.session.take() {
            Some(session) => self.finish(Ok(session)),
            None => self.finish(Err(CancelError::AlreadyFinished)),
        }
    }
}

impl Operation for CancelCapture {
    type Output = CancelOutcome;

    fn start(&mut self) -> Action<CancelOutcome> {
        if !matches!(self.state, CancelState::NotStarted) {
            return self.finish(Err(CancelError::AlreadyFinished));
        }
        self.state = CancelState::WaitingReply;
        Action::Send(frame::build_cancel_capture_mid(self.handle))
    }

    fn step(&mut self, event: Event) -> Action<CancelOutcome> {
        match std::mem::replace(&mut self.state, CancelState::Done) {
            CancelState::NotStarted => self.finish(Err(CancelError::UnexpectedEvent)),
            CancelState::WaitingReply => match event {
                // The cancel is plain: its reply carries no wrapped sequence, whatever its body.
                Event::Reply { status, .. } if status == proto::status::OK => self.succeed(),
                Event::Reply { status, .. } => {
                    self.begin_teardown(CancelError::SensorStatus(status))
                }
                Event::ReplyWithoutBody => self.succeed(),
                Event::Transport(error) => self.begin_teardown(CancelError::Transport(error)),
                Event::Cancelled => self.begin_teardown(CancelError::Cancelled),
                Event::Finger => self.begin_teardown(CancelError::UnexpectedEvent),
            },
            CancelState::TearingDown {
                original,
                mut teardown,
            } => match teardown.step(event) {
                Action::Send(frame) => {
                    self.state = CancelState::TearingDown { original, teardown };
                    Action::Send(frame)
                }
                // Teardown never waits; anything but another send is its end.
                _ => self.finish(Err(original)),
            },
            CancelState::Done => self.finish(Err(CancelError::AlreadyFinished)),
        }
    }
}

//! Events the transport hands to the core, and the actions the core asks of it.
//!
//! The core never performs I/O and knows nothing about USB. A transport turns one transfer into
//! one [`Event`]; the core answers with the next [`Action`]. Timeouts, threads and callbacks live
//! in the transport, never here.

use std::fmt;

/// A transport failure, classified by what the caller can do about it.
///
/// This is the core's own type: the probe's [`crate::Event`] users map their USB error onto it,
/// so the core never depends on a transport crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// A transfer did not complete in its window.
    Timeout,
    /// The sensor left the bus.
    Disconnected,
    /// An endpoint stalled.
    Stall,
    /// Anything else, with the transport's own description.
    Other(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("transfer timed out"),
            Self::Disconnected => f.write_str("sensor disconnected"),
            Self::Stall => f.write_str("endpoint stalled"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TransportError {}

/// Something that happened outside the core that the operation must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A reply arrived with a body. `status` is the command status from the reply frame header
    /// (offset 20), not the interrupt announcement's status word.
    Reply { status: u32, body: Vec<u8> },
    /// The transport completed the command without an announced body.
    ReplyWithoutBody,
    /// The sensor signalled that a finger was read.
    Finger,
    /// The transport failed. The operation decides whether any teardown still makes sense.
    Transport(TransportError),
    /// The operation was cancelled. Only a finger wait is cancellable; a command transfer never is.
    Cancelled,
}

/// What the core wants the transport to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<R> {
    /// Send these bytes as one command frame, then deliver the reply as an [`Event`].
    Send(Vec<u8>),
    /// Wait for the next finger event. The wait, and its timeout, belong to the transport.
    WaitFinger,
    /// The operation is over. The value is its result.
    Finish(R),
}

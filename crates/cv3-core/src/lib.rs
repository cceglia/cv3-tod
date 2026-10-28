//! I/O-free protocol core for the Broadcom ControlVault 3 fingerprint sensor.
//!
//! The core performs no I/O. It consumes events from a transport and returns the action that
//! transport should perform next, which keeps every parser and state machine testable against
//! recorded frames and without hardware. See `docs/adr/0001-io-free-core-with-c-shim.md`.
//!
//! Two transports drive it: `cvctl`, the development probe, and the libfprint TOD plugin.
//!
//! An operation is one object with [`Operation::start`] and [`Operation::step`]; [`handshake`] is
//! the first. Events and actions are [`Event`] and [`Action`]; the core's transport failure type
//! is [`TransportError`], never a USB crate's.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod event;
pub mod frame;
pub mod handshake;
pub mod operation;
pub mod proto;
pub mod session;

pub use event::{Action, Event, TransportError};
pub use handshake::{Handshake, HandshakeError};
pub use operation::Operation;
pub use session::{
    CloseError, CloseSession, OpenError, OpenSession, Session, SessionKey, UnwrapError, WrapError,
};

/// Version of the core crate, reported by the probe.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

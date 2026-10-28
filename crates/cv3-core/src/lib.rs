//! I/O-free protocol core for the Broadcom ControlVault 3 fingerprint sensor.
//!
//! The core performs no I/O. It consumes events from a transport and returns the action that
//! transport should perform next, which keeps every parser and state machine testable against
//! recorded frames and without hardware. See `docs/adr/0001-io-free-core-with-c-shim.md`.
//!
//! Two transports drive it: `cvctl`, the development probe, and the libfprint TOD plugin.

pub mod frame;
pub mod proto;

/// Version of the core crate, reported by the probe.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! The shape every core operation has.
//!
//! One object owns one operation's state. `start` returns the first action; every later `step`
//! consumes exactly one event and returns exactly one action. There is no callback, no thread and
//! no timer: the transport owns time, and the caller drives the loop.
//!
//! Later operations (opening a session, capture, enrolment, matching) implement the same trait, so
//! the probe and the C shim run them with one loop and one vocabulary:
//!
//! ```text
//! let mut action = operation.start();
//! loop {
//!     match action {
//!         Action::Send(frame) => action = operation.step(transport.send(&frame)),
//!         Action::WaitFinger   => action = operation.step(transport.wait_finger()),
//!         Action::Finish(result) => break result,
//!     }
//! }
//! ```
//!
//! # Contract
//!
//! * `start` is called once, on a fresh operation.
//! * `step` is called only after `start`, with the event matching the action it returned.
//! * After a `Finish`, the operation is inert: calling `step` again must not panic; it returns a
//!   `Finish` carrying that operation's "already finished" result. No operation may index a
//!   buffer or unwrap a length it has not validated.

use crate::event::{Action, Event};

/// One protocol operation, driven only by events.
pub trait Operation {
    /// The operation's final value, delivered in [`Action::Finish`].
    type Output;

    /// Returns the first action.
    fn start(&mut self) -> Action<Self::Output>;

    /// Consumes one event and returns the next action.
    fn step(&mut self, event: Event) -> Action<Self::Output>;
}

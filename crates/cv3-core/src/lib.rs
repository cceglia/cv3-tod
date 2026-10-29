//! I/O-free protocol core for the Broadcom ControlVault 3 fingerprint sensor.
//!
//! The core performs no I/O. It consumes events from a transport and returns the action that
//! transport should perform next, which keeps every parser and state machine testable against
//! recorded frames and without hardware. See `docs/adr/0001-io-free-core-with-c-shim.md`.
//!
//! Two transports drive it: `cvctl`, the development probe, and the libfprint TOD plugin. Both
//! implement [`Transport`] and share [`transport::run`].
//!
//! An operation is one object with [`Operation::start`] and [`Operation::step`]; [`handshake`] is
//! the first. Events and actions are [`Event`] and [`Action`]; the core's transport failure type
//! is [`TransportError`], never a USB crate's.
//!
//! [`ScriptedTransport`], [`FailingTransport`] and the replay transport in [`transcript`]
//! are test support: the same contract tests run against every implementation, and a recorded
//! session replays without hardware.

#![forbid(unsafe_code)]

pub mod cancel;
pub mod capture;
pub mod crypto;
pub mod enrol;
pub mod event;
pub mod frame;
pub mod handshake;
pub mod inventory;
pub mod operation;
pub mod print;
pub mod proto;
pub mod session;
pub mod tlv;
pub mod transcript;
pub mod transport;
pub mod verify;

pub use cancel::{CancelCapture, CancelError};
pub use capture::{
    ArmCapture, ArmOutcome, CAPTURE_PLAINTEXT_LEN, CAPTURE_TLV_LEN, Capture, CaptureError,
    CapturedSample, SAMPLE_HASH_LEN, capture_tlv, find_tlv_value,
};
pub use enrol::{
    COMMIT_PLAINTEXT_LEN, COMMIT_TLV_LEN, DISCARD_PLAINTEXT_LEN, DISCARD_TLV_LEN, Enrol,
    EnrolError, EnrolProgress, EnrolStage, EnrolledTemplate, MAX_ACCEPTED_SAMPLES,
    MAX_CAPTURE_ATTEMPTS, START_TLV_LEN, TEMPLATE_ID_LEN, TemplateSource, UPDATE_PLAINTEXT_LEN,
    UPDATE_TLV_LEN, commit_tlv, discard_tlv, enrol_iv, start_tlv, update_tlv,
};
pub use event::{Action, Event, TransportError};
pub use handshake::{Handshake, HandshakeError};
pub use inventory::{
    INVENTORY_PLAINTEXT_LEN, INVENTORY_TLV_LEN, Inventory, InventoryError, InventoryReply,
    TLV_ALIGNMENT, TLV_HEADER_LEN, TlvEntry, TlvScan, inventory_tlv, scan_tlv,
};
pub use operation::Operation;
pub use print::{
    MATCH_REPLY_PLAINTEXT_LEN, PRINT_MAGIC, PRINT_PAYLOAD_LEN, PRINT_VERSION, PayloadError,
    PrintPayload, PrintSource,
};
pub use session::{
    CloseError, CloseSession, OpenError, OpenSession, SequenceRule, Session, SessionKey, Teardown,
    TeardownError, UnwrapError, WrapError,
};
pub use transcript::{
    Divergence, FrameKey, RecordingTransport, ReplayTransport, Transcript, TranscriptError,
    TranscriptRecord,
};
pub use transport::{FailingTransport, ScriptedOutcome, ScriptedTransport, Transport};
pub use verify::{
    MATCH_VALUE_LEN, MATCHED_HANDLE_OFFSET, Match, MatchError, VERDICT_MATCH, VERDICT_NO_MATCH,
    VERDICT_OFFSET, Verdict, Verification, Verify, VerifyError, request_tlv,
};

/// Version of the core crate, reported by the probe.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

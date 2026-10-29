//! The C boundary.
//!
//! Directions are fixed: `libfprint` calls the exported entry point, the shim's GObject code runs
//! in C, and the shim's vfuncs call the functions below. One opaque `Cv3Tod` per `FpDevice`
//! instance owns every piece of protocol state; what crosses the boundary is only that pointer and
//! a [`Cv3Action`] describing the next USB transfer or the final result. The C side never parses a
//! frame, computes a length, performs cryptography or keeps session state.
//!
//! Buffers always belong to Rust. An action that needs one carries a pointer to an allocation this
//! module made; C hands it to `fpi_usb_transfer_fill_*_full` with a NULL free function and reports
//! the actual length back through [`cv3_tod_on_transfer`], where the allocation is reclaimed. The
//! buffer is a separate allocation, never a field of the `Cv3Tod` that the same call mutably
//! borrows, so the pointer C hands back cannot alias Rust's state.
//!
//! Transfer ownership is C's, and the rule is fixed: `fpi_usb_transfer_new` returns one reference
//! and `fpi_usb_transfer_submit` **consumes** it, so a submitted transfer is never unreffed by the
//! shim. libfprint's completion wrapper drops that reference after the callback returns. Only a
//! transfer that was never submitted is the shim's to free. Unreffing a submitted one is a
//! use-after-free in the completion, which is what the class harness's refcount check catches.
//!
//! Enrolment adds two accessors instead of widening the action: [`cv3_tod_take_progress`] hands C
//! the stages to report to `fpi_device_enroll_progress`, and [`cv3_tod_take_payload`] hands it the
//! bound print record once the enrolment has succeeded. Verification takes the opposite direction:
//! [`cv3_tod_verify_start`] receives the `fpi-data` bytes C read off the `FpPrint`, and Rust decodes
//! the record and decides which match id to ask about.

use std::ptr;

use cv3_core::proto::endpoint;
use cv3_wire::{IoFailure, IoReply, Transfer};

use crate::plugin::{OutcomeKind, Plugin, Step};

/// glib's `GType`: an opaque, non-zero integer naming a registered GObject type.
///
/// `gsize` is `usize`, and glib guarantees a `GType` is never zero, but the value is only ever
/// produced and consumed by C here, so it stays opaque.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GType(usize);

// SAFETY: the declaration matches the C definition in `shim/cv3_tod.c`, which `build.rs`
// compiles from the same crate. Both return glib's `GType`, an unsigned integer of pointer size.
#[cfg(not(test))]
unsafe extern "C" {
    /// Registers the plugin's `FpDevice` subclass on first call and returns its `GType`.
    pub safe fn cv3_tod_shim_get_type() -> GType;
}

/// The symbol `libfprint`'s TOD loader resolves in the plugin.
///
/// The body is the C shim's, but the symbol is exported from Rust: rustc gives a `cdylib` a
/// linker version script listing only the symbols the Rust crate declares, so a C-defined entry
/// point would be hidden inside the shared object.
#[cfg(not(test))]
#[unsafe(export_name = "fpi_tod_shared_driver_get_type")]
pub extern "C" fn entry_point() -> GType {
    cv3_tod_shim_get_type()
}

/// Bytes available for the finish message, terminator included.
pub const MESSAGE_LEN: usize = 256;

/// What C should do with the action. The numbers match `Cv3ActionKind` in the shim.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Out = 0,
    InterruptIn = 1,
    BulkIn = 2,
    Control = 3,
    Finish = 4,
    /// An interrupt read of the finger event: the one transfer C may cancel.
    WaitFinger = 5,
}

/// The result C reports for one transfer. The numbers match `Cv3IoResult` in the shim.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoResultKind {
    Completed = 0,
    Data = 1,
    Failed = 2,
}

/// The transport failure C classifies a `GError` into. The numbers match `Cv3IoError` in the shim.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoErrorCode {
    Timeout = 0,
    Disconnected = 1,
    Cancelled = 2,
    Busy = 3,
    Stall = 4,
    Other = 5,
}

/// One instruction for the shim: perform a transfer or finish the operation.
///
/// The Rust compiler checks the layout here and the C compiler checks the same size and the
/// message offset in the shim, so a field added on one side fails the build on the other.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cv3Action {
    pub kind: u32,
    pub endpoint: u8,
    pub request_type: u8,
    pub request: u8,
    /// One when C must perform this transfer with the action's cancellable; zero otherwise.
    ///
    /// Only the finger wait may be cancelled. A command transfer handed a cancellable is what
    /// deep-wedges this sensor when it is aborted, so C must never cancel anything else.
    pub cancellable: u8,
    pub value: u16,
    pub index: u16,
    pub timeout_ms: u32,
    pub buffer: *mut u8,
    pub length: usize,
    /// Zero for a successful finish, one for a failed one.
    pub status: i32,
    /// The [`OutcomeKind`] value when `status` is non-zero.
    pub error_code: i32,
    pub message: [u8; MESSAGE_LEN],
}

const _: () = assert!(std::mem::size_of::<Cv3Action>() == 296);
const _: () = assert!(std::mem::offset_of!(Cv3Action, message) == 40);

/// One device's protocol state. Opaque to C.
pub struct Cv3Tod {
    plugin: Plugin,
    pending: Option<PendingBuffer>,
}

/// A buffer handed to C and not yet returned.
struct PendingBuffer {
    ptr: *mut u8,
    len: usize,
}

impl Cv3Tod {
    fn new() -> Self {
        Self {
            plugin: Plugin::new(),
            pending: None,
        }
    }

    /// Turns one step into the action C performs, allocating an IN/OUT buffer if it needs one.
    fn publish(&mut self, step: Step) -> Cv3Action {
        self.release_pending();
        match step {
            Step::Transfer(transfer) => match transfer {
                Transfer::Out { frame, timeout_ms } => {
                    let (buffer, length) = self.store_buffer(frame);
                    Cv3Action {
                        kind: ActionKind::Out as u32,
                        endpoint: endpoint::OUT,
                        timeout_ms,
                        buffer,
                        length,
                        ..Cv3Action::empty()
                    }
                }
                Transfer::InterruptIn {
                    max_len,
                    timeout_ms,
                } => {
                    let (buffer, length) = self.store_buffer(vec![0u8; max_len]);
                    Cv3Action {
                        kind: ActionKind::InterruptIn as u32,
                        endpoint: endpoint::INTERRUPT,
                        timeout_ms,
                        buffer,
                        length,
                        ..Cv3Action::empty()
                    }
                }
                Transfer::FingerIn { timeout_ms } => {
                    let (buffer, length) =
                        self.store_buffer(vec![0u8; cv3_wire::INTERRUPT_BUFFER_LEN]);
                    Cv3Action {
                        kind: ActionKind::WaitFinger as u32,
                        endpoint: endpoint::INTERRUPT,
                        timeout_ms,
                        buffer,
                        length,
                        cancellable: 1,
                        ..Cv3Action::empty()
                    }
                }
                Transfer::BulkIn { len, timeout_ms } => {
                    let (buffer, length) = self.store_buffer(vec![0u8; len]);
                    Cv3Action {
                        kind: ActionKind::BulkIn as u32,
                        endpoint: endpoint::IN,
                        timeout_ms,
                        buffer,
                        length,
                        ..Cv3Action::empty()
                    }
                }
                Transfer::ControlOut {
                    request_type,
                    request,
                    value,
                    index,
                    timeout_ms,
                } => Cv3Action {
                    kind: ActionKind::Control as u32,
                    endpoint: endpoint::INTERRUPT,
                    request_type,
                    request,
                    value,
                    index,
                    timeout_ms,
                    ..Cv3Action::empty()
                },
            },
            Step::Finished(outcome) => Cv3Action {
                kind: ActionKind::Finish as u32,
                status: i32::from(outcome.kind != OutcomeKind::Ok),
                error_code: outcome.kind as i32,
                message: message_bytes(&outcome.message),
                ..Cv3Action::empty()
            },
        }
    }

    /// Moves `bytes` into a heap allocation C can write into and returns its raw parts.
    fn store_buffer(&mut self, bytes: Vec<u8>) -> (*mut u8, usize) {
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed).cast::<u8>();
        self.pending = Some(PendingBuffer { ptr, len });
        (ptr, len)
    }

    /// Reclaims the last buffer, if C has not returned it yet.
    ///
    /// This runs at the top of [`Self::publish`], which the shim calls from inside libfprint's
    /// transfer callback, so the previous transfer's bytes are freed before libfprint's completion
    /// wrapper drops the transfer. The order is safe: the shim fills transfers with a NULL free
    /// function (libfprint never owns the buffer) and libfprint does not touch `transfer->buffer`
    /// after the callback returns, so nothing reads this allocation after it is freed.
    fn release_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            // SAFETY: the pointer and length came from `Box::into_raw` of a `[u8]` in
            // `store_buffer`, this is the only place that frees it, and `pending` is cleared
            // first so a double free cannot happen.
            unsafe {
                drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                    pending.ptr,
                    pending.len,
                )));
            }
        }
    }

    /// Reclaims the buffer and returns its bytes, truncated to what C actually transferred.
    fn take_buffer(&mut self, actual_length: usize) -> Vec<u8> {
        let Some(pending) = self.pending.take() else {
            return Vec::new();
        };
        // SAFETY: as in `release_pending`; the length is the allocation's own length.
        let boxed =
            unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(pending.ptr, pending.len)) };
        let mut bytes = Vec::from(boxed);
        bytes.truncate(actual_length.min(bytes.len()));
        bytes
    }
}

impl Drop for Cv3Tod {
    fn drop(&mut self) {
        self.release_pending();
    }
}

impl Cv3Action {
    fn empty() -> Self {
        Self {
            kind: ActionKind::Finish as u32,
            endpoint: 0,
            request_type: 0,
            request: 0,
            cancellable: 0,
            value: 0,
            index: 0,
            timeout_ms: 0,
            buffer: ptr::null_mut(),
            length: 0,
            status: 0,
            error_code: 0,
            message: [0u8; MESSAGE_LEN],
        }
    }

    fn error(message: &str) -> Self {
        Self {
            kind: ActionKind::Finish as u32,
            status: 1,
            error_code: OutcomeKind::General as i32,
            message: message_bytes(message),
            ..Self::empty()
        }
    }
}

/// Copies `message` into the action's fixed field, on a character boundary and NUL terminated.
fn message_bytes(message: &str) -> [u8; MESSAGE_LEN] {
    let mut out = [0u8; MESSAGE_LEN];
    let bytes = message.as_bytes();
    let mut end = bytes.len().min(MESSAGE_LEN - 1);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    out[..end].copy_from_slice(&bytes[..end]);
    out
}

fn failure(code: IoErrorCode) -> IoFailure {
    match code {
        IoErrorCode::Timeout => IoFailure::Timeout,
        IoErrorCode::Disconnected => IoFailure::Disconnected,
        IoErrorCode::Cancelled => IoFailure::Cancelled,
        IoErrorCode::Busy => IoFailure::Busy,
        IoErrorCode::Stall => IoFailure::Stall,
        IoErrorCode::Other => IoFailure::Other("USB transfer failed".to_owned()),
    }
}

fn result_kind(result: u32) -> Option<IoResultKind> {
    match result {
        0 => Some(IoResultKind::Completed),
        1 => Some(IoResultKind::Data),
        2 => Some(IoResultKind::Failed),
        _ => None,
    }
}

fn error_code(code: u32) -> Option<IoErrorCode> {
    match code {
        0 => Some(IoErrorCode::Timeout),
        1 => Some(IoErrorCode::Disconnected),
        2 => Some(IoErrorCode::Cancelled),
        3 => Some(IoErrorCode::Busy),
        4 => Some(IoErrorCode::Stall),
        5 => Some(IoErrorCode::Other),
        _ => None,
    }
}

/// Creates one device's session state. C owns the pointer until [`cv3_tod_destroy`].
#[unsafe(no_mangle)]
pub extern "C" fn cv3_tod_create() -> *mut Cv3Tod {
    Box::into_raw(Box::new(Cv3Tod::new()))
}

/// Frees the state, including a buffer C never returned.
///
/// # Safety
///
/// `tod` must be null or a pointer from [`cv3_tod_create`] that has not been destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_destroy(tod: *mut Cv3Tod) {
    if tod.is_null() {
        return;
    }
    // SAFETY: the caller passes the pointer `cv3_tod_create` returned and does not use it again.
    unsafe {
        drop(Box::from_raw(tod));
    }
}

/// Starts the handshake and returns the first transfer.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_open_start(tod: *mut Cv3Tod) -> Cv3Action {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    match unsafe { tod.as_mut() } {
        Some(session) => {
            let step = session.plugin.open_start();
            session.publish(step)
        }
        None => Cv3Action::error("cv3: the plugin session was not created"),
    }
}

/// Reports one finished transfer and returns the next step.
///
/// `actual_length` is the number of bytes C transferred; it is only used for an IN result. The
/// `result` and `error` numbers are the shim's own small enums, never a `GError` code.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_on_transfer(
    tod: *mut Cv3Tod,
    result: u32,
    error: u32,
    actual_length: usize,
) -> Cv3Action {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    let Some(session) = (unsafe { tod.as_mut() }) else {
        return Cv3Action::error("cv3: the plugin session was not created");
    };
    let reply = match result_kind(result) {
        Some(IoResultKind::Completed) => IoReply::Completed,
        Some(IoResultKind::Data) => IoReply::Data(session.take_buffer(actual_length)),
        Some(IoResultKind::Failed) => match error_code(error) {
            Some(code) => IoReply::Failed(failure(code)),
            None => IoReply::Failed(IoFailure::Other(format!(
                "USB transfer failed with code {error}"
            ))),
        },
        None => IoReply::Failed(IoFailure::Other(format!(
            "USB transfer reported unknown result {result}"
        ))),
    };
    let step = session.plugin.on_transfer(reply);
    session.publish(step)
}

/// Releases a live session with the plain `0x04`, or finishes at once when none is open.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_close_start(tod: *mut Cv3Tod) -> Cv3Action {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    match unsafe { tod.as_mut() } {
        Some(session) => {
            let step = session.plugin.close_start();
            session.publish(step)
        }
        None => Cv3Action {
            kind: ActionKind::Finish as u32,
            ..Cv3Action::empty()
        },
    }
}

/// The number of enrolment stages the plugin declares to `libfprint`.
///
/// It comes from the core's own [`cv3_core::bind::ENROL_STAGES`], so the shim's class and the
/// operation's stage reports cannot disagree.
#[unsafe(no_mangle)]
pub extern "C" fn cv3_tod_enrol_stages() -> i32 {
    i32::try_from(cv3_core::bind::ENROL_STAGES).unwrap_or(i32::MAX)
}

/// Starts a whole enrolment on the live session and returns the first transfer.
///
/// A failure before the first transfer comes back as a [`ActionKind::Finish`] action with a
/// message; the shim reports it as the enrolment's failure.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_enrol_start(tod: *mut Cv3Tod) -> Cv3Action {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    match unsafe { tod.as_mut() } {
        Some(session) => {
            let step = session.plugin.enrol_start();
            session.publish(step)
        }
        None => Cv3Action::error("cv3: the plugin session was not created"),
    }
}

/// Starts a verification of the print whose stored record is `payload` on the live session.
///
/// `payload` is the `fpi-data` byte array libfprint keeps on the print; this call decodes it and
/// the record decides which match id the sensor is asked about. Nothing on the C side interprets
/// the bytes. An empty payload finishes at once with [`OutcomeKind::DataNotFound`] and a payload
/// that is not this driver's record with [`OutcomeKind::DataInvalid`], both as a finish action.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`]; `payload` must be null or point to
/// `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_verify_start(
    tod: *mut Cv3Tod,
    payload: *const u8,
    len: usize,
) -> Cv3Action {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    let Some(session) = (unsafe { tod.as_mut() }) else {
        return Cv3Action::error("cv3: the plugin session was not created");
    };
    // SAFETY: the caller guarantees `payload` points to `len` readable bytes (or is null, which
    // `from_raw_parts` tolerates only for a zero length; both cases are mapped to an empty slice).
    let bytes: &[u8] = if payload.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(payload, len) }
    };
    let step = session.plugin.verify_start(bytes);
    session.publish(step)
}

/// Takes the next progress report for `fpi_device_enroll_progress`.
///
/// Returns `0` when there is nothing to report, `1` for a completed stage and `2` for a rejected
/// sample the client should retry. `completed` receives the stage count, always at most
/// [`cv3_core::bind::ENROL_STAGES`].
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`]; `completed` must be null or point
/// to a writable `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_take_progress(tod: *mut Cv3Tod, completed: *mut i32) -> i32 {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    let Some(session) = (unsafe { tod.as_mut() }) else {
        return 0;
    };
    let Some(progress) = session.plugin.take_progress() else {
        return 0;
    };
    if !completed.is_null() {
        // SAFETY: the caller guarantees `completed` is writable.
        unsafe {
            *completed = i32::try_from(progress.completed).unwrap_or(i32::MAX);
        }
    }
    if progress.retry { 2 } else { 1 }
}

/// Copies the bound print record of a completed enrolment into `destination`.
///
/// Returns the number of bytes written, or `0` when there is no payload or `destination` is too
/// small. The shim calls this only after a successful finish action.
///
/// # Safety
///
/// `tod` must be null or a live pointer from [`cv3_tod_create`]; `destination` must be null or
/// valid for writes of `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cv3_tod_take_payload(
    tod: *mut Cv3Tod,
    destination: *mut u8,
    capacity: usize,
) -> usize {
    // SAFETY: the caller guarantees `tod` is live; `as_mut` is null safe.
    let Some(session) = (unsafe { tod.as_mut() }) else {
        return 0;
    };
    let Some(payload) = session.plugin.take_payload() else {
        return 0;
    };
    if destination.is_null() || capacity < payload.len() {
        return 0;
    }
    // SAFETY: `destination` is valid for `capacity` bytes and `payload` is a distinct local array.
    unsafe {
        ptr::copy_nonoverlapping(payload.as_ptr(), destination, payload.len());
    }
    payload.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice;

    #[test]
    fn the_action_layout_is_the_one_the_shim_static_asserts() {
        assert_eq!(std::mem::size_of::<Cv3Action>(), 296);
        assert_eq!(std::mem::offset_of!(Cv3Action, buffer), 16);
        assert_eq!(std::mem::offset_of!(Cv3Action, length), 24);
        assert_eq!(std::mem::offset_of!(Cv3Action, status), 32);
        assert_eq!(std::mem::offset_of!(Cv3Action, error_code), 36);
        assert_eq!(std::mem::offset_of!(Cv3Action, message), 40);
    }

    #[test]
    fn an_overlong_message_is_truncated_on_a_character_boundary() {
        let text = "cv3: ".to_owned() + &"é".repeat(300);
        let message = message_bytes(&text);
        assert_eq!(message[MESSAGE_LEN - 1], 0, "NUL terminated");
        let end = message.iter().position(|byte| *byte == 0).expect("NUL");
        assert!(std::str::from_utf8(&message[..end]).is_ok());
        assert!(end < MESSAGE_LEN);
    }

    #[test]
    fn a_transfer_action_carries_the_endpoint_and_the_buffer() {
        let mut session = Cv3Tod::new();
        let action = session.publish(Step::Transfer(Transfer::Out {
            frame: vec![1, 2, 3],
            timeout_ms: 5_000,
        }));

        assert_eq!(action.kind, ActionKind::Out as u32);
        assert_eq!(action.endpoint, endpoint::OUT);
        assert_eq!(action.length, 3);
        assert!(!action.buffer.is_null());
        assert_eq!(action.timeout_ms, 5_000);
        // SAFETY: the buffer is this action's own allocation, still pending.
        assert_eq!(
            unsafe { slice::from_raw_parts(action.buffer, 3) },
            [1, 2, 3]
        );
    }

    #[test]
    fn a_finished_action_carries_the_status_and_the_message() {
        let mut session = Cv3Tod::new();
        let action = session.publish(Step::Finished(crate::plugin::Outcome {
            kind: OutcomeKind::Proto,
            message: "cv3: refused".to_owned(),
        }));

        assert_eq!(action.kind, ActionKind::Finish as u32);
        assert_eq!(action.status, 1);
        assert_eq!(action.error_code, OutcomeKind::Proto as i32);
        let end = action.message.iter().position(|byte| *byte == 0).unwrap();
        assert_eq!(&action.message[..end], b"cv3: refused");
    }

    #[test]
    fn a_finger_wait_action_is_the_one_cancellable_transfer() {
        let mut session = Cv3Tod::new();
        let action = session.publish(Step::Transfer(Transfer::FingerIn {
            timeout_ms: cv3_core::proto::timeout::FINGER_MS,
        }));

        assert_eq!(action.kind, ActionKind::WaitFinger as u32);
        assert_eq!(action.endpoint, endpoint::INTERRUPT);
        assert_eq!(action.cancellable, 1);
        assert_eq!(action.timeout_ms, cv3_core::proto::timeout::FINGER_MS);
        assert_eq!(action.length, cv3_wire::INTERRUPT_BUFFER_LEN);
        assert!(!action.buffer.is_null());
    }

    #[test]
    fn every_command_action_is_non_cancellable() {
        let mut session = Cv3Tod::new();
        for transfer in [
            Transfer::Out {
                frame: vec![0; 16],
                timeout_ms: 5_000,
            },
            Transfer::InterruptIn {
                max_len: 64,
                timeout_ms: 60_000,
            },
            Transfer::BulkIn {
                len: 4,
                timeout_ms: 60_000,
            },
            Transfer::ControlOut {
                request_type: 0x40,
                request: 0x0d,
                value: 1,
                index: 2,
                timeout_ms: 1_000,
            },
        ] {
            let action = session.publish(Step::Transfer(transfer));
            assert_eq!(action.cancellable, 0, "kind {}", action.kind);
        }
    }

    #[test]
    fn the_declared_stage_count_is_the_core_value() {
        assert_eq!(cv3_tod_enrol_stages(), 13);
        assert_eq!(
            usize::try_from(cv3_tod_enrol_stages()).expect("a positive count"),
            cv3_core::bind::ENROL_STAGES
        );
    }

    #[test]
    fn a_verify_start_without_a_payload_or_session_is_an_error_not_a_panic() {
        let mut session = Cv3Tod::new();
        // SAFETY: `session` is live; a NULL payload with zero length is explicitly allowed.
        let action = unsafe { cv3_tod_verify_start(&mut session, ptr::null(), 0) };
        assert_eq!(action.kind, ActionKind::Finish as u32);
        assert_eq!(action.error_code, OutcomeKind::General as i32);
        let end = action.message.iter().position(|byte| *byte == 0).unwrap();
        assert!(
            std::str::from_utf8(&action.message[..end])
                .expect("a message")
                .contains("session"),
            "the error says the session is the problem"
        );
    }

    #[test]
    fn the_enrolment_accessors_are_empty_and_null_safe_before_a_run() {
        let mut session = Cv3Tod::new();
        let mut completed = -1;
        // SAFETY: `session` is a live `Cv3Tod` and `completed` is a local `i32`.
        assert_eq!(
            unsafe { cv3_tod_take_progress(&mut session, &mut completed) },
            0
        );
        assert_eq!(completed, -1, "nothing is written without a report");
        // SAFETY: `session` is live; a NULL destination is explicitly allowed.
        assert_eq!(
            unsafe { cv3_tod_take_payload(&mut session, ptr::null_mut(), 0) },
            0
        );
    }
}

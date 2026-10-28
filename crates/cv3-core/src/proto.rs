//! Wire constants for the ControlVault 3 command protocol.
//!
//! These are observations of the wire format, not vendor material. Frame layout is documented in
//! [`crate::frame`]; the values here name the places inside it.

/// Commands, as the little-endian `u16` at header offset 8.
pub mod cmd {
    /// Host → sensor: begin the ECDH handshake with a 20-byte host nonce.
    pub const CHALLENGE: u16 = 0x23;
    /// Host → sensor: answer the challenge with a host nonce and public key.
    pub const CHALLENGE_RESPONSE: u16 = 0x24;
    /// Open the secure session (wrapped).
    pub const OPEN_SESSION: u16 = 0x02;
    /// Close the session once no capture is pending.
    pub const CLOSE_SESSION: u16 = 0x04;
    /// Arm a capture (wrapped); the reply carries a sample hash.
    pub const ARM_CAPTURE: u16 = 0x66;
    /// Cancel an armed capture.
    pub const CANCEL_CAPTURE: u16 = 0x68;
    /// Discard a half-finished enrolment.
    pub const DISCARD_ENROLMENT: u16 = 0x6D;
    /// Start a new enrolment.
    pub const START_ENROLMENT: u16 = 0x8A;
    /// Submit one captured sample to the enrolment.
    pub const UPDATE_ENROLMENT: u16 = 0x6C;
    /// Commit the enrolment, storing the template.
    pub const COMMIT_ENROLMENT: u16 = 0x6E;
    /// Verify one captured finger against one template: the vendor's `cv_do_fingerprint_verify`
    /// sends this, and its request carries the optional template id.
    pub const VERIFY: u16 = 0x72;
    /// Identify the captured finger against the sensor's store: the vendor's
    /// `cv_do_fingerprint_identify` sends this one-to-many request, which ticket 20 owns.
    pub const IDENTIFY: u16 = 0x73;
    /// Query the sensor's template inventory (reply format not yet decoded).
    pub const INVENTORY: u16 = 0x2F;
}

/// Attribute byte at header offset 10. A command's attribute is part of its identity: the same
/// command number with the wrong attribute is a different, rejected request.
pub mod attr {
    pub const CHALLENGE: u8 = 0x41;
    pub const CHALLENGE_RESPONSE: u8 = 0x01;
    /// Wrapped commands scoped to the session.
    pub const SESSION: u8 = 0x45;
    /// Wrapped commands that arm or consume a capture.
    pub const CAPTURE: u8 = 0x47;
    /// Cancel while a session handle is still live.
    pub const CANCEL_SESSION: u8 = 0x40;
    /// Cancel with no session handle in the header.
    pub const CANCEL_SESSIONLESS: u8 = 0x44;
    /// Start an enrolment: the same attribute byte as the sessionless cancel, but the command is
    /// `0x8A` and it carries a zero parameter block, not a handle.
    pub const ENROLMENT_START: u8 = 0x44;
    pub const CLOSE_SESSION: u8 = 0x40;
    pub const INVENTORY: u8 = 0x42;
}

/// Encoding byte at header offset 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encoding {
    /// Parameters are sent as-is.
    Plain = 0x00,
    /// Parameters are AES-128-CBC ciphertext preceded by an IV, with a MAC inside the plaintext.
    ///
    /// This is what the host sends on a wrapped command.
    Wrapped = 0x02,
    /// The same wrapped body as [`Self::Wrapped`], as the sensor sends it: AES-128-CBC ciphertext
    /// preceded by an IV, with no token inside the plaintext.
    ///
    /// Host → sensor wrapped commands use `0x02`; sensor → host wrapped replies were measured to
    /// use `0x03` on 2026-10-28. The reference ignores this byte and decrypts any body long enough
    /// to hold an IV and a ciphertext block, so the direction is the only thing it distinguishes.
    WrappedReply = 0x03,
    /// Close-session frame: parameters are plaintext but the frame is not a normal command.
    CloseHandle = 0x04,
}

impl Encoding {
    /// Whether `byte` is either direction's wrapped encoding: [`Self::Wrapped`] on a command,
    /// [`Self::WrappedReply`] on a reply.
    pub fn is_wrapped(byte: u8) -> bool {
        byte == Self::Wrapped as u8 || byte == Self::WrappedReply as u8
    }
}

/// Status word at header offset 20. Zero is success; these are the values the protocol uses to
/// say "not now" rather than "no".
pub mod status {
    /// Success.
    pub const OK: u32 = 0x00;
    /// Wrapped command rejected: the wrap sequence did not match the sensor's expectation.
    pub const BAD_SEQUENCE: u32 = 0x0F;
    /// A capture is already armed; cancel it, then re-arm.
    pub const CAPTURE_PENDING: u32 = 0x85;
    /// The sensor will accept no further samples of this enrolment.
    pub const ENROLMENT_FULL: u32 = 0x8C;
    /// Sample accepted but the enrolment is not complete.
    pub const SAMPLE_ACCEPTED: u32 = 0x8F;
    /// Rescan: the sample was unusable.
    pub const RESCAN_A: u32 = 0xA4;
    /// Rescan: the sample was unusable.
    pub const RESCAN_B: u32 = 0x89;
    /// The second status the sensor answers the `0x72` verify with. The vendor's
    /// `cv_do_fingerprint_verify` special-cases it next to `0x00`, so the driver treats it as
    /// "the sensor answered" and decodes the reply body; what it means for the verdict is not
    /// established here, and [`VERIFY_ANSWERED`](Self::VERIFY_ANSWERED) names only that handling.
    pub const VERIFY_ANSWERED: u32 = 0x89;
}

/// USB endpoints: commands go out on bulk `0x01`, replies arrive on bulk `0x81`, and the sensor
/// signals asynchronously (reply length, finger event) on interrupt `0x85`.
pub mod endpoint {
    pub const OUT: u8 = 0x01;
    pub const IN: u8 = 0x81;
    pub const INTERRUPT: u8 = 0x85;
}

/// Event values the sensor signals on the interrupt endpoint after a command announces a zero-length
/// reply, as the finger wait does.
pub mod interrupt {
    /// The sensor read the finger that was armed.
    pub const FINGER: u32 = 0x03;
}

/// Vendor and product of the only sensor this driver claims.
pub const VENDOR_ID: u16 = 0x0a5c;
pub const PRODUCT_ID: u16 = 0x5843;

/// Transfer timeouts in milliseconds.
///
/// The command timeouts are deliberately generous: a short bulk-OUT timeout aborts the URB
/// mid-flight, which deep-wedges this sensor. See `docs/` for the recovery ladder.
pub mod timeout {
    pub const COMMAND_MS: u32 = 5_000;
    pub const REPLY_MS: u32 = 60_000;
    pub const FINGER_MS: u32 = 30_000;
    pub const TEARDOWN_MS: u32 = 3_000;
}

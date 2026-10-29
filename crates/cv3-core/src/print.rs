//! The per-print record a stored print carries, and the id check verification relies on.
//!
//! `libfprint` stores whatever bytes the driver gives it for a print. This module is that fixed,
//! versioned record: a magic and version, the enrolment id (or the sample hash used in its place),
//! the **match id** the confirmation touch returned, and flags saying which id is which and that
//! the print is bound.
//!
//! ```text
//! +0   4  magic "CV3P"
//! +4   1  version (1)
//! +5   1  flags: bit 0 bound, bit 1 source (0 = sensor enrolment id, 1 = sample hash)
//! +6  20  enrolment id, or the sample hash that stood in for it
//! +26  4  match id, the `0x6E` reply's template handle (little-endian)
//! ```
//!
//! The record is fixed and dependency-free on purpose: no JSON, no schema, and an unknown version
//! is refused rather than guessed. [`PrintPayload::decode`] checks every field's bounds, so a
//! truncated, foreign or newer payload is a typed error and never a panic.
//!
//! # What [`PrintPayload::accepts`] is for
//!
//! The sensor's match flag alone is not enough. A verification is accepted only when the print is
//! bound **and** the reply carries exactly the shape the match measured on 2026-10-29 produces:
//! two `(0,4,…)` entries — the verdict and the match id — followed by the 32-byte token, with the
//! verdict `1` and the id equal to the one recorded at enrolment. An altered flag that leaves out
//! the id therefore fails, and a different finger's template cannot satisfy this print's id.
//!
//! The limits are real and stated rather than papered over: the confirmation touch cannot be
//! proven to be the same finger as the twelve enrolment samples, and this comparison cannot detect
//! a whole reply replayed from an earlier successful verification.

use crate::session::TOKEN_LEN;
use crate::verify::{MATCHED_HANDLE_OFFSET, VERDICT_MATCH, VERDICT_OFFSET, Verdict};

/// Magic at the start of every print payload.
pub const PRINT_MAGIC: [u8; 4] = *b"CV3P";
/// The only payload version this driver writes.
pub const PRINT_VERSION: u8 = 1;
/// Bytes one encoded print payload occupies.
pub const PRINT_PAYLOAD_LEN: usize = 4 + 1 + 1 + 20 + 4;

/// Bytes of a match reply that carries the verified structure: two `(0,4,…)` entries and the token.
pub const MATCH_REPLY_PLAINTEXT_LEN: usize = 12 + 12 + TOKEN_LEN;

/// Which id names the template in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintSource {
    /// The 20-byte enrolment id the `0x6C` completion reply reported.
    EnrolmentId,
    /// The last accepted sample hash, used when the sensor never named an enrolment id.
    SampleHash,
}

/// Why a print payload could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// Fewer bytes than [`PRINT_PAYLOAD_LEN`].
    TooShort { got: usize, need: usize },
    /// More bytes than [`PRINT_PAYLOAD_LEN`]; a payload is a fixed record.
    TooLong { got: usize, need: usize },
    /// The magic is not [`PRINT_MAGIC`].
    BadMagic,
    /// A version this driver does not know, including a newer one.
    UnknownVersion(u8),
    /// Bits outside the two defined flag bits are set.
    UnknownFlags(u8),
    /// The record says the print is not bound; an unbound print can never verify.
    Unbound,
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { got, need } => {
                write!(f, "print payload is {got} bytes, {need} are required")
            }
            Self::TooLong { got, need } => {
                write!(
                    f,
                    "print payload is {got} bytes, exactly {need} are required"
                )
            }
            Self::BadMagic => f.write_str("print payload does not start with CV3P"),
            Self::UnknownVersion(version) => {
                write!(f, "unknown print payload version {version}")
            }
            Self::UnknownFlags(flags) => write!(f, "unknown print payload flags {flags:#04x}"),
            Self::Unbound => f.write_str("print payload is not bound to a match id"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// One stored print's binding: what was enrolled and the id the sensor matched it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintPayload {
    enrolment_id: [u8; 20],
    source: PrintSource,
    match_id: u32,
}

impl PrintPayload {
    /// A bound print. There is deliberately no constructor for an unbound one: the driver refuses
    /// to store a print whose confirmation did not produce an id.
    pub fn bound(enrolment_id: [u8; 20], source: PrintSource, match_id: u32) -> Self {
        Self {
            enrolment_id,
            source,
            match_id,
        }
    }

    /// The enrolment id, or the sample hash that stood in for it.
    pub fn enrolment_id(&self) -> &[u8; 20] {
        &self.enrolment_id
    }

    /// Whether [`Self::enrolment_id`] is the sensor's enrolment id or a sample hash.
    pub fn source(&self) -> PrintSource {
        self.source
    }

    /// The template handle the confirmation touch matched.
    pub fn match_id(&self) -> u32 {
        self.match_id
    }

    /// Encodes the record into the fixed [`PRINT_PAYLOAD_LEN`] bytes.
    pub fn encode(&self) -> [u8; PRINT_PAYLOAD_LEN] {
        let mut out = [0u8; PRINT_PAYLOAD_LEN];
        out[..4].copy_from_slice(&PRINT_MAGIC);
        out[4] = PRINT_VERSION;
        out[5] = 0x01
            | match self.source {
                PrintSource::EnrolmentId => 0x00,
                PrintSource::SampleHash => 0x02,
            };
        out[6..26].copy_from_slice(&self.enrolment_id);
        out[26..30].copy_from_slice(&self.match_id.to_le_bytes());
        out
    }

    /// Reads a payload, refusing anything that is not exactly this version's bound record.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.len() < PRINT_PAYLOAD_LEN {
            return Err(PayloadError::TooShort {
                got: bytes.len(),
                need: PRINT_PAYLOAD_LEN,
            });
        }
        if bytes.len() > PRINT_PAYLOAD_LEN {
            return Err(PayloadError::TooLong {
                got: bytes.len(),
                need: PRINT_PAYLOAD_LEN,
            });
        }
        if bytes[..4] != PRINT_MAGIC {
            return Err(PayloadError::BadMagic);
        }
        if bytes[4] != PRINT_VERSION {
            return Err(PayloadError::UnknownVersion(bytes[4]));
        }
        let flags = bytes[5];
        if flags & !0x03 != 0 {
            return Err(PayloadError::UnknownFlags(flags));
        }
        if flags & 0x01 == 0 {
            return Err(PayloadError::Unbound);
        }
        let source = if flags & 0x02 == 0 {
            PrintSource::EnrolmentId
        } else {
            PrintSource::SampleHash
        };
        let mut enrolment_id = [0u8; 20];
        enrolment_id.copy_from_slice(&bytes[6..26]);
        let match_id = u32::from_le_bytes([bytes[26], bytes[27], bytes[28], bytes[29]]);
        Ok(Self {
            enrolment_id,
            source,
            match_id,
        })
    }

    /// Whether `verdict` is a genuine match for this print.
    ///
    /// Requires the exact reply the sensor was measured to send — two `(0,4,…)` entries and the
    /// token — the verdict `1`, and the match id equal to the one recorded at enrolment. A refusal,
    /// a no-match, a reply of another shape and a different template's id all return `false`.
    pub fn accepts(&self, verdict: &Verdict) -> bool {
        verdict.plaintext_len == MATCH_REPLY_PLAINTEXT_LEN
            && verdict.word == VERDICT_MATCH
            && verdict.matched_handle == Some(self.match_id)
            && verdict
                .plaintext
                .as_ref()
                .is_some_and(|plaintext| structured_match_reply(plaintext))
    }
}

/// Whether `plaintext` is `(0,4,word) (0,4,id)` followed by the token, with nothing else.
fn structured_match_reply(plaintext: &[u8]) -> bool {
    if plaintext.len() != MATCH_REPLY_PLAINTEXT_LEN {
        return false;
    }
    let verdict = le32(plaintext, 0) == 0 && le32(plaintext, 4) == 4;
    let handle = le32(plaintext, 12) == 0 && le32(plaintext, 16) == 4;
    verdict
        && handle
        && VERDICT_OFFSET == 8
        && MATCHED_HANDLE_OFFSET == 20
        && le32(plaintext, 8) == VERDICT_MATCH
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::status;

    const ENROLMENT_ID: [u8; 20] = [0xa5; 20];
    const MATCH_ID: u32 = 0x0070_69a9;

    fn payload() -> PrintPayload {
        PrintPayload::bound(ENROLMENT_ID, PrintSource::EnrolmentId, MATCH_ID)
    }

    /// The measured match reply: `(0,4,1) (0,4,match id)` and 32 token bytes.
    fn match_reply(word: u32, handle: u32) -> Vec<u8> {
        let mut plaintext = vec![0u8; MATCH_REPLY_PLAINTEXT_LEN];
        plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
        plaintext[8..12].copy_from_slice(&word.to_le_bytes());
        plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
        plaintext[20..24].copy_from_slice(&handle.to_le_bytes());
        plaintext
    }

    fn verdict(word: u32, handle: Option<u32>, plaintext: Vec<u8>) -> Verdict {
        Verdict {
            command: crate::proto::cmd::IDENTIFY_HANDLES,
            status: status::OK,
            word,
            matched: word == VERDICT_MATCH,
            matched_handle: handle,
            plaintext_len: plaintext.len(),
            plaintext: Some(plaintext),
            reply_len: 0,
        }
    }

    #[test]
    fn a_bound_print_round_trips_through_its_payload() {
        for source in [PrintSource::EnrolmentId, PrintSource::SampleHash] {
            let print = PrintPayload::bound(ENROLMENT_ID, source, MATCH_ID);
            let decoded = PrintPayload::decode(&print.encode()).expect("the payload decodes");
            assert_eq!(decoded, print);
            assert_eq!(decoded.source(), source);
            assert_eq!(decoded.enrolment_id(), &ENROLMENT_ID);
            assert_eq!(decoded.match_id(), MATCH_ID);
        }
    }

    #[test]
    fn the_encoded_shape_is_fixed_and_documented() {
        let encoded = payload().encode();
        assert_eq!(encoded.len(), 30);
        assert_eq!(&encoded[..4], b"CV3P");
        assert_eq!(encoded[4], 1, "version");
        assert_eq!(encoded[5], 0x01, "bound, enrolment id");
        assert_eq!(&encoded[6..26], &ENROLMENT_ID);
        assert_eq!(&encoded[26..30], &MATCH_ID.to_le_bytes());
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_guessed() {
        let mut encoded = payload().encode();
        encoded[4] = 2;
        assert_eq!(
            PrintPayload::decode(&encoded),
            Err(PayloadError::UnknownVersion(2))
        );
    }

    #[test]
    fn foreign_and_malformed_payloads_are_typed_errors() {
        let mut encoded = payload().encode();
        encoded[0] = b'X';
        assert_eq!(PrintPayload::decode(&encoded), Err(PayloadError::BadMagic));

        let mut encoded = payload().encode();
        encoded[5] = 0x04;
        assert_eq!(
            PrintPayload::decode(&encoded),
            Err(PayloadError::UnknownFlags(0x04))
        );

        let mut encoded = payload().encode();
        encoded[5] = 0x02;
        assert_eq!(PrintPayload::decode(&encoded), Err(PayloadError::Unbound));

        assert_eq!(
            PrintPayload::decode(&payload().encode()[..29]),
            Err(PayloadError::TooShort { got: 29, need: 30 })
        );

        let mut encoded = payload().encode().to_vec();
        encoded.push(0);
        assert_eq!(
            PrintPayload::decode(&encoded),
            Err(PayloadError::TooLong { got: 31, need: 30 })
        );
    }

    #[test]
    fn the_recorded_match_id_accepts_the_measured_match_reply() {
        let print = payload();
        let plaintext = match_reply(1, MATCH_ID);

        assert!(print.accepts(&verdict(1, Some(MATCH_ID), plaintext)));
    }

    #[test]
    fn a_no_match_is_refused() {
        let print = payload();
        let plaintext = match_reply(0, 0);

        assert!(!print.accepts(&verdict(0, Some(0), plaintext)));
    }

    #[test]
    fn another_templates_id_is_refused() {
        let print = payload();
        let plaintext = match_reply(1, 0x002f_1a08);

        assert!(!print.accepts(&verdict(1, Some(0x002f_1a08), plaintext)));
    }

    #[test]
    fn a_reply_of_another_shape_is_refused() {
        let print = payload();

        // The verdict word without the id entry: a flag flip that leaves the id out.
        let mut short = match_reply(1, MATCH_ID);
        short.truncate(12);
        assert!(!print.accepts(&verdict(1, None, short)));

        // The right values, but the token is missing, so the reply is not the measured shape.
        let mut long = match_reply(1, MATCH_ID);
        long.extend_from_slice(&[0u8; 16]);
        assert!(!print.accepts(&verdict(1, Some(MATCH_ID), long)));
    }

    #[test]
    fn a_verdict_without_a_plaintext_is_refused() {
        let print = payload();
        let mut unread = verdict(1, Some(MATCH_ID), match_reply(1, MATCH_ID));
        unread.plaintext = None;

        assert!(!print.accepts(&unread));
    }
}

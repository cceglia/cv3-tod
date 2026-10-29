//! A best-effort scan of a decrypted reply as a sequence of little-endian TLVs.
//!
//! Both the `0x2F` inventory reply and the verify and commit diagnostics are device bytes whose
//! shape is not established yet, so they share one scanner. [`scan_tlv`] is pure and deliberately
//! separate from every operation: it walks the plaintext four bytes at a time, reading a
//! little-endian `u32 tag`, `u32 length` and the declared value. It never indexes past the buffer
//! and never panics on device bytes: a declared value longer than what remains is reported as
//! truncated, and trailing bytes too short for a header are counted rather than decoded.
//!
//! Nothing here interprets what an entry means. Whether a tag names a template, a verdict or a
//! handle is a question for the tickets that own those replies.

/// Length of a TLV entry header: a little-endian `u32 tag` and `u32 declared length`.
pub const TLV_HEADER_LEN: usize = 8;
/// The alignment the TLV scan advances by after each entry.
pub const TLV_ALIGNMENT: usize = 4;

/// One entry the scan found.
///
/// `value` is the bytes that are actually present, which is shorter than [`Self::declared_len`]
/// when the device's length ran past the end of the plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvEntry<'a> {
    /// Offset of the entry's eight-byte header in the plaintext.
    pub offset: usize,
    /// The little-endian tag at the start of the header.
    pub tag: u32,
    /// The little-endian length the header declares.
    pub declared_len: u32,
    /// The value bytes present in the plaintext, at most `declared_len` long.
    pub value: &'a [u8],
}

impl TlvEntry<'_> {
    /// Whether the header declared more value bytes than the plaintext holds.
    pub fn is_truncated(&self) -> bool {
        self.value.len() < self.declared_len as usize
    }
}

/// The result of [`scan_tlv`]: every entry found, plus what could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvScan<'a> {
    /// The entries, in plaintext order.
    pub entries: Vec<TlvEntry<'a>>,
    /// Bytes after the last entry that are too short for an eight-byte header.
    pub trailing: usize,
    /// Whether an entry's declared value ran past the end of the plaintext.
    pub truncated: bool,
}

/// Scans a decrypted reply as a sequence of 4-byte-aligned TLVs.
///
/// The scan starts at offset zero and, after each entry, advances by `8 + declared length`
/// rounded up to the next four-byte boundary. Every read is bounded by the plaintext length, so
/// empty, short, arbitrary and lying input returns a report instead of panicking. An entry whose
/// value does not fit is recorded with the bytes that are present and sets
/// [`TlvScan::truncated`]; the scan then stops.
pub fn scan_tlv(plaintext: &[u8]) -> TlvScan<'_> {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut at = 0usize;

    while at + TLV_HEADER_LEN <= plaintext.len() {
        let tag = le32(plaintext, at);
        let declared_len = le32(plaintext, at + 4);
        let value_start = at + TLV_HEADER_LEN;
        let available = plaintext.len() - value_start;
        let declared = declared_len as usize;
        let take = declared.min(available);

        entries.push(TlvEntry {
            offset: at,
            tag,
            declared_len,
            value: &plaintext[value_start..value_start + take],
        });

        if declared > available {
            truncated = true;
            at = plaintext.len();
            break;
        }

        let Some(advance) = TLV_HEADER_LEN.checked_add(declared) else {
            truncated = true;
            at = plaintext.len();
            break;
        };
        let Some(next) = at.checked_add(advance) else {
            truncated = true;
            at = plaintext.len();
            break;
        };
        let padded = next + (TLV_ALIGNMENT - next % TLV_ALIGNMENT) % TLV_ALIGNMENT;
        if padded > plaintext.len() {
            // The last entry's value ends the plaintext; any alignment padding is absent.
            at = plaintext.len();
            break;
        }
        at = padded;
    }

    TlvScan {
        entries,
        trailing: plaintext.len().saturating_sub(at),
        truncated,
    }
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

    #[test]
    fn an_empty_or_short_plaintext_scans_to_nothing() {
        for length in 0..TLV_HEADER_LEN {
            let bytes = vec![0xff; length];
            let scan = scan_tlv(&bytes);
            assert!(scan.entries.is_empty(), "length {length}");
            assert_eq!(scan.trailing, length);
            assert!(!scan.truncated, "length {length}");
        }
    }

    #[test]
    fn a_declared_value_that_runs_past_the_end_is_truncated_not_read() {
        let mut plaintext = vec![0u8; 13];
        plaintext[4..8].copy_from_slice(&20u32.to_le_bytes());
        plaintext[8..13].copy_from_slice(&[1, 2, 3, 4, 5]);

        let scan = scan_tlv(&plaintext);
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].value, &[1, 2, 3, 4, 5]);
        assert!(scan.entries[0].is_truncated());
        assert!(scan.truncated);
    }

    #[test]
    fn entries_advance_by_the_declared_length_rounded_to_four() {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&1u32.to_le_bytes());
        plaintext.extend_from_slice(&5u32.to_le_bytes());
        plaintext.extend_from_slice(&[0xaa; 5]);
        plaintext.extend_from_slice(&[0u8; 3]);
        plaintext.extend_from_slice(&7u32.to_le_bytes());
        plaintext.extend_from_slice(&0u32.to_le_bytes());

        let scan = scan_tlv(&plaintext);
        assert_eq!(scan.entries.len(), 2);
        assert_eq!(scan.entries[1].offset, 16);
        assert_eq!(scan.entries[1].tag, 7);
    }
}

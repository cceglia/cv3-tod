//! Identification: one capture and one match against every print a client offers.
//!
//! The client (libfprint's `identify` call) supplies a gallery of `FpPrint`s. Each print carries the
//! fixed [`PrintPayload`](crate::print::PrintPayload) record enrolment stored, whose match id is the
//! template handle the confirmation touch measured. Identification turns those handles into one
//! `0x2F` request:
//!
//! ```text
//! host → sensor  0x66 wrapped, attr 0x47   arm a capture (a [`Capture`](crate::capture::Capture))
//! sensor → host                             the finger event
//! host → sensor  0x2F wrapped, attr 0x47   identify against the gallery's u32 handles
//! sensor → host  wrapped reply             verdict and matched handle
//! ```
//!
//! It is exactly the [`Verify`] sequence with a longer type-2 handle array: [`Identify`] composes
//! one `Verify`, and [`Gallery::matched_index`] decides whether the reply named a gallery print.
//! The reply must have the measured shape, verdict `1` and a handle that is one of the candidates;
//! anything else is a no-match. A match for a handle that is not in the gallery is never a match.
//!
//! # Independence from the sensor's inventory
//!
//! Nothing here sends or decodes the inventory query (`0x2F` with attr `0x42`), and nothing depends
//! on whether it was decoded. The handles come from the stored prints themselves, which is why
//! identification works in the host-stored fallback too (SPEC "Storage model").
//!
//! # An unusable gallery
//!
//! Payloads are decoded here, in Rust. A print whose record is missing, foreign, another version,
//! unbound, or bound to handle `0` is not a candidate; neither is either copy of a handle that two
//! prints share, because the reply could not say which print it meant. A gallery with no candidate
//! produces [`IdentifyOutcome::EmptyGallery`] without touching the sensor: no capture is armed and
//! no command is sent.
//!
//! # Ownership
//!
//! [`Identify`] owns the [`Session`] until it finishes. Every outcome returns it still open; a
//! failure comes from [`Verify`], whose own teardown has already run, so there is no session to
//! return. The caller must not close a session it was not given back.

use std::collections::HashMap;
use std::fmt;

use crate::crypto;
use crate::event::{Action, Event};
use crate::operation::Operation;
use crate::print::PrintPayload;
use crate::proto::cmd;
use crate::session::Session;
use crate::verify::{Verdict, Verification, Verify, VerifyError};

/// One print a client offered for identification, and where it sits in the client's gallery.
///
/// `index` is the position in the gallery the caller passed to `libfprint`, not a position among
/// the usable prints: it is what the caller needs back to name the exact `FpPrint` that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GalleryEntry<'a> {
    index: usize,
    payload: &'a [u8],
}

impl<'a> GalleryEntry<'a> {
    /// Names one gallery print by its position and the bytes of its stored record.
    pub fn new(index: usize, payload: &'a [u8]) -> Self {
        Self { index, payload }
    }

    /// The print's position in the caller's gallery.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The `fpi-data` bytes the caller read off the print; may be empty or foreign.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// One gallery print that identification may match, with its original gallery position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    index: usize,
    print: PrintPayload,
}

impl Candidate {
    /// The print's position in the caller's gallery.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The decoded, bound record.
    pub fn print(&self) -> &PrintPayload {
        &self.print
    }

    /// The template handle the sensor is asked about.
    pub fn handle(&self) -> u32 {
        self.print.match_id()
    }
}

/// The usable prints of a client-supplied gallery.
///
/// Order follows the gallery, duplicates and unusable records are dropped. The type has no
/// unbound mode: a bound record is the only thing [`PrintPayload::decode`] returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gallery {
    candidates: Vec<Candidate>,
}

impl Gallery {
    /// Decodes every entry and keeps the prints that can honestly be matched.
    ///
    /// A record is kept only when [`PrintPayload::decode`] accepts it, its handle is not zero (the
    /// sensor's no-match sentinel, never a template), and no other kept print names the same
    /// handle. A duplicate handle is ambiguous: the sensor's reply could not say which print it
    /// meant, so neither print is a candidate.
    pub fn from_entries(entries: &[GalleryEntry<'_>]) -> Self {
        let decoded: Vec<Candidate> = entries
            .iter()
            .filter_map(|entry| {
                PrintPayload::decode(entry.payload())
                    .ok()
                    .filter(|print| print.match_id() != 0)
                    .map(|print| Candidate {
                        index: entry.index(),
                        print,
                    })
            })
            .collect();

        let mut counts: HashMap<u32, usize> = HashMap::with_capacity(decoded.len());
        for candidate in &decoded {
            *counts.entry(candidate.handle()).or_default() += 1;
        }

        Self {
            candidates: decoded
                .into_iter()
                .filter(|candidate| counts.get(&candidate.handle()) == Some(&1))
                .collect(),
        }
    }

    /// The prints identification may match, in gallery order.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Whether the gallery has no usable print.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Every candidate's template handle, in gallery order.
    pub fn handles(&self) -> impl Iterator<Item = u32> + '_ {
        self.candidates.iter().map(Candidate::handle)
    }

    /// The gallery position of the print `verdict` matched, if any.
    ///
    /// [`PrintPayload::accepts`] is the one acceptance rule: the measured reply shape, verdict `1`
    /// and the print's own recorded handle. A verdict `1` naming a handle outside the gallery is
    /// therefore a no-match, never a match.
    pub fn matched_index(&self, verdict: &Verdict) -> Option<usize> {
        self.candidates
            .iter()
            .find(|candidate| candidate.print.accepts(verdict))
            .map(Candidate::index)
    }
}

/// How one identification ended.
///
/// Every variant carries the still-open [`Session`] the operation owned; the caller may run the
/// next operation on it. `Matched` and `NoMatch` are both successful sensor exchanges. Only the
/// latter two are possible with a usable gallery; `EmptyGallery` is the no-match an unusable
/// gallery produces without sending anything.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentifyOutcome {
    /// The sensor answered a match for the print at this gallery position.
    Matched {
        /// The matched print's position in the caller's gallery.
        index: usize,
        /// What the sensor answered, for the caller's diagnostics.
        verdict: Verdict,
        /// The session, still open.
        session: Session,
    },
    /// The sensor answered, but not with a match for any gallery print.
    NoMatch {
        /// What the sensor answered, including its raw verdict word and handle.
        verdict: Verdict,
        /// The session, still open.
        session: Session,
    },
    /// No print in the gallery had a usable bound record, so nothing was captured or sent.
    EmptyGallery {
        /// The session, untouched and still open.
        session: Session,
    },
}

/// Why an identification did not produce an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyError {
    /// The capture or match failed; [`Verify`]'s teardown has already run.
    Verify(VerifyError),
    /// An event that cannot occur in this state arrived.
    UnexpectedEvent,
    /// `start` or `step` was called after the operation finished.
    AlreadyFinished,
}

impl fmt::Display for IdentifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verify(error) => write!(f, "identification failed: {error}"),
            Self::UnexpectedEvent => f.write_str("unexpected event during identification"),
            Self::AlreadyFinished => f.write_str("operation has already finished"),
        }
    }
}

impl std::error::Error for IdentifyError {}

type IdentifyResult = Result<IdentifyOutcome, IdentifyError>;

enum IdentifyState {
    NotStarted,
    Matching(Box<Verify>),
    Done,
}

/// A whole identification: one [`Verify`] whose match request carries every gallery handle.
///
/// The caller supplies one IV per wrapped request, because the core generates no randomness. A
/// gallery with no usable print finishes at `start` without a transfer and returns the session
/// untouched.
pub struct Identify {
    session: Option<Session>,
    gallery: Gallery,
    capture_iv: [u8; crypto::BLOCK_LEN],
    match_iv: [u8; crypto::BLOCK_LEN],
    state: IdentifyState,
}

impl Identify {
    /// Builds an identification over `gallery` for a live session.
    pub fn new(
        session: Session,
        gallery: Gallery,
        capture_iv: [u8; crypto::BLOCK_LEN],
        match_iv: [u8; crypto::BLOCK_LEN],
    ) -> Self {
        Self {
            session: Some(session),
            gallery,
            capture_iv,
            match_iv,
            state: IdentifyState::NotStarted,
        }
    }

    fn finish(&mut self, result: IdentifyResult) -> Action<IdentifyResult> {
        self.state = IdentifyState::Done;
        Action::Finish(result)
    }

    fn start_matching(&mut self) -> Action<IdentifyResult> {
        let Some(session) = self.session.take() else {
            return self.finish(Err(IdentifyError::AlreadyFinished));
        };
        if self.gallery.is_empty() {
            return self.finish(Ok(IdentifyOutcome::EmptyGallery { session }));
        }

        let mut verify = Verify::new(session, self.capture_iv, self.match_iv)
            .with_template_handles(self.gallery.handles())
            .with_command(cmd::IDENTIFY_HANDLES);
        self.advance(verify.start(), verify)
    }

    fn advance(
        &mut self,
        action: Action<Result<Verification, VerifyError>>,
        verify: Verify,
    ) -> Action<IdentifyResult> {
        match action {
            Action::Send(frame) => {
                self.state = IdentifyState::Matching(Box::new(verify));
                Action::Send(frame)
            }
            Action::WaitFinger => {
                self.state = IdentifyState::Matching(Box::new(verify));
                Action::WaitFinger
            }
            Action::Finish(result) => self.on_matched(result),
        }
    }

    fn on_matched(&mut self, result: Result<Verification, VerifyError>) -> Action<IdentifyResult> {
        let verification = match result {
            Ok(verification) => verification,
            Err(error) => return self.finish(Err(IdentifyError::Verify(error))),
        };
        let Verification { verdict, session } = verification;
        let outcome = match self.gallery.matched_index(&verdict) {
            Some(index) => IdentifyOutcome::Matched {
                index,
                verdict,
                session,
            },
            None => IdentifyOutcome::NoMatch { verdict, session },
        };
        self.finish(Ok(outcome))
    }
}

impl Operation for Identify {
    type Output = IdentifyResult;

    fn start(&mut self) -> Action<IdentifyResult> {
        if !matches!(self.state, IdentifyState::NotStarted) {
            return self.finish(Err(IdentifyError::AlreadyFinished));
        }
        self.start_matching()
    }

    fn step(&mut self, event: Event) -> Action<IdentifyResult> {
        match std::mem::replace(&mut self.state, IdentifyState::Done) {
            IdentifyState::NotStarted => self.finish(Err(IdentifyError::UnexpectedEvent)),
            IdentifyState::Matching(mut verify) => {
                let action = verify.step(event);
                self.advance(action, *verify)
            }
            IdentifyState::Done => self.finish(Err(IdentifyError::AlreadyFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::print::{MATCH_REPLY_PLAINTEXT_LEN, PRINT_PAYLOAD_LEN, PrintSource};
    use crate::proto::status;
    use crate::verify::{MATCHED_HANDLE_OFFSET, VERDICT_MATCH, VERDICT_NO_MATCH, VERDICT_OFFSET};

    const FIRST_HANDLE: u32 = 0x0070_69a9;
    const SECOND_HANDLE: u32 = 0x002f_1a08;

    fn record(handle: u32) -> Vec<u8> {
        PrintPayload::bound([0xa5; 20], PrintSource::EnrolmentId, handle)
            .encode()
            .to_vec()
    }

    fn unbound_record(handle: u32) -> Vec<u8> {
        let mut bytes = record(handle);
        bytes[5] &= !0x01;
        bytes
    }

    fn entries<'a>(payloads: &'a [Vec<u8>]) -> Vec<GalleryEntry<'a>> {
        payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| GalleryEntry::new(index, payload))
            .collect()
    }

    fn reply(word: u32, handle: u32) -> Vec<u8> {
        let mut plaintext = vec![0u8; MATCH_REPLY_PLAINTEXT_LEN];
        plaintext[4..8].copy_from_slice(&4u32.to_le_bytes());
        plaintext[VERDICT_OFFSET..VERDICT_OFFSET + 4].copy_from_slice(&word.to_le_bytes());
        plaintext[16..20].copy_from_slice(&4u32.to_le_bytes());
        plaintext[MATCHED_HANDLE_OFFSET..MATCHED_HANDLE_OFFSET + 4]
            .copy_from_slice(&handle.to_le_bytes());
        plaintext
    }

    fn verdict(word: u32, handle: u32) -> Verdict {
        Verdict {
            command: cmd::IDENTIFY_HANDLES,
            status: status::OK,
            word,
            matched: word == VERDICT_MATCH,
            matched_handle: Some(handle),
            plaintext: Some(reply(word, handle)),
            plaintext_len: MATCH_REPLY_PLAINTEXT_LEN,
            reply_len: 0,
        }
    }

    #[test]
    fn usable_prints_keep_their_gallery_positions() {
        let payloads = [record(FIRST_HANDLE), record(SECOND_HANDLE)];
        let gallery = Gallery::from_entries(&entries(&payloads));

        assert_eq!(
            gallery
                .candidates()
                .iter()
                .map(|candidate| (candidate.index(), candidate.handle()))
                .collect::<Vec<_>>(),
            [(0, FIRST_HANDLE), (1, SECOND_HANDLE)]
        );
        assert_eq!(
            gallery.handles().collect::<Vec<_>>(),
            [FIRST_HANDLE, SECOND_HANDLE]
        );
    }

    #[test]
    fn unusable_records_are_not_candidates() {
        let unbound = unbound_record(SECOND_HANDLE);
        let mut foreign = record(SECOND_HANDLE);
        foreign[0] = b'X';
        let mut other_version = record(SECOND_HANDLE);
        other_version[4] = 2;
        let short = vec![0u8; PRINT_PAYLOAD_LEN - 1];

        for payload in [&[][..], &unbound, &foreign, &other_version, &short] {
            let gallery = Gallery::from_entries(&[GalleryEntry::new(0, payload)]);
            assert!(
                gallery.is_empty(),
                "payload {payload:02x?} must be unusable"
            );
        }
    }

    #[test]
    fn a_zero_handle_is_the_no_match_sentinel_not_a_candidate() {
        let payloads = [record(0)];
        assert!(Gallery::from_entries(&entries(&payloads)).is_empty());
    }

    #[test]
    fn either_copy_of_a_duplicate_handle_is_dropped() {
        let payloads = [
            record(FIRST_HANDLE),
            record(FIRST_HANDLE),
            record(SECOND_HANDLE),
        ];
        let gallery = Gallery::from_entries(&entries(&payloads));

        assert_eq!(
            gallery.candidates().len(),
            1,
            "the duplicated print is ambiguous"
        );
        assert_eq!(gallery.candidates()[0].index(), 2);
        assert_eq!(gallery.candidates()[0].handle(), SECOND_HANDLE);

        // The duplicated handle cannot match, even though the sensor names it.
        assert_eq!(
            gallery.matched_index(&verdict(VERDICT_MATCH, FIRST_HANDLE)),
            None
        );
        assert_eq!(
            gallery.matched_index(&verdict(VERDICT_MATCH, SECOND_HANDLE)),
            Some(2)
        );
    }

    #[test]
    fn the_matched_index_is_the_one_which_accepts_the_reply() {
        let payloads = [record(FIRST_HANDLE), record(SECOND_HANDLE)];
        let gallery = Gallery::from_entries(&entries(&payloads));

        assert_eq!(
            gallery.matched_index(&verdict(VERDICT_MATCH, SECOND_HANDLE)),
            Some(1)
        );
        assert_eq!(gallery.matched_index(&verdict(VERDICT_NO_MATCH, 0)), None);
        assert_eq!(
            gallery.matched_index(&verdict(VERDICT_MATCH, 0x0bad_f00d)),
            None,
            "a handle outside the gallery is not a match"
        );
    }

    #[test]
    fn a_verdict_without_the_measured_shape_is_not_a_match() {
        let payloads = [record(FIRST_HANDLE)];
        let gallery = Gallery::from_entries(&entries(&payloads));
        let mut short = verdict(VERDICT_MATCH, FIRST_HANDLE);
        short.plaintext = Some(vec![0u8; 28]);
        short.plaintext_len = 28;

        assert_eq!(gallery.matched_index(&short), None);
    }
}

//! The host timestamp the sensor asks for on interrupt type 5.
//!
//! `0x85` normally carries a reply announcement or a finger event, but the Windows driver also
//! treats a first word of `5` as `CV_GET_HOST_TIMESTAMP_INTERRUPT` and answers it with a vendor
//! device control request. Broadcom's Linux driver does not, so the request is left unanswered and
//! the next bulk read times out. This module packs the value and demultiplexes the event before a
//! real announcement or finger event reaches [`crate::exchange::Exchange`].
//!
//! The vendor packs **local** civil time; this probe packs **UTC**, because a [`SystemTime`] has no
//! timezone. The bit positions and widths are what the controller consumes, and they are the same
//! either way. See `docs/protocol-notes.md`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::usb::UsbError;

/// `CV_GET_HOST_TIMESTAMP_INTERRUPT`: the first `u32` of an interrupt payload.
pub const HOST_TIMESTAMP_INTERRUPT: u32 = 5;

/// The vendor/device OUT request that carries the timestamp, with no data stage.
pub const HOST_TIMESTAMP_REQUEST: u8 = 0x0d;

/// How long the host-side control transfer may take. It is a control request, not a command.
pub const SYNC_TIMEOUT_MS: u64 = 1_000;

/// How many host-timestamp requests one read may answer before giving up.
///
/// Four is more than the sensor was ever seen to send in a row; the bound only exists so a stuck
/// controller cannot keep the probe looping forever.
pub const MAX_REQUESTS: usize = 4;

/// Packs `time` as the little-endian `u32` the controller expects.
///
/// Fields, least significant bit first: day 0..4, month 5..8, year since 2000 9..14, hour 15..19,
/// minute 20..25, second 26..31. The year field is six bits, so a date outside 2000..=2063
/// saturates to the nearest end of that range; every other field is taken from the UTC civil date.
pub fn pack(time: SystemTime) -> u32 {
    let seconds = unix_seconds(time);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    let (year, month, day) = civil_from_days(days);
    let year_since_2000 = (year - 2000).clamp(0, 63) as u32;

    (day & 0x1f)
        | ((month & 0x0f) << 5)
        | (year_since_2000 << 9)
        | ((hour as u32) << 15)
        | ((minute as u32) << 20)
        | ((second as u32) << 26)
}

/// Whether an interrupt payload starts with a host-timestamp request.
///
/// A shorter payload is not a request: it cannot carry the type word, and the exchange reports it
/// as a short announcement or finger event instead.
pub fn is_host_timestamp_request(payload: &[u8]) -> bool {
    payload.len() >= 4
        && u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            == HOST_TIMESTAMP_INTERRUPT
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => {
            let before = error.duration();
            let seconds = before.as_secs() as i64;
            if before.subsec_nanos() == 0 {
                -seconds
            } else {
                -seconds - 1
            }
        }
    }
}

/// The civil date for a count of days since 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (year + i64::from(month <= 2), month, day)
}

/// One interrupt source that can be read and answered with the host timestamp.
///
/// This is the internal seam the demultiplexing is tested through: the real transport wraps an
/// interrupt endpoint and the demux tests wrap a scripted queue. Both the announcement read and
/// the finger wait use it, so a type-5 event is answered wherever it arrives.
pub(crate) trait TimestampInterrupt {
    fn read_interrupt(&mut self) -> Result<Vec<u8>, UsbError>;
    fn answer_timestamp(&mut self) -> Result<(), UsbError>;
}

/// Reads until a payload that is not a host-timestamp request and returns it.
///
/// A request is answered and the read retried, up to [`MAX_REQUESTS`]. A failed answer is returned
/// as its own transport error: the caller must not mistake an unanswered request for a reply.
pub(crate) fn demux_interrupt(source: &mut impl TimestampInterrupt) -> Result<Vec<u8>, UsbError> {
    let mut answered = 0;
    loop {
        let payload = source.read_interrupt()?;
        if !is_host_timestamp_request(&payload) {
            return Ok(payload);
        }
        if answered == MAX_REQUESTS {
            return Err(UsbError::TimestampRequests);
        }
        answered += 1;
        source.answer_timestamp()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn the_year_2000_epoch_packs_to_the_first_day_of_the_first_month() {
        // 2000-01-01 00:00:00 UTC: day 1 at bit 0 and month 1 at bit 5.
        assert_eq!(pack(at(946_684_800)), 0x0000_0021);
    }

    #[test]
    fn a_leap_day_keeps_its_day_and_month_fields() {
        // 2000-02-29 00:00:00 UTC: day 29, month 2, year since 2000 = 0.
        assert_eq!(pack(at(951_782_400)), 0x0000_005d);
    }

    #[test]
    fn a_later_leap_day_packs_every_field() {
        // 2024-02-29 12:34:56 UTC: day 29, month 2, year 24, 12:34:56.
        assert_eq!(pack(at(1_709_210_096)), 0xe226_305d);
    }

    #[test]
    fn an_ordinary_date_packs_utc_fields() {
        // 2026-10-28 20:40:00 UTC.
        assert_eq!(pack(at(1_793_220_000)), 0x028a_355c);
    }

    #[test]
    fn a_year_before_the_field_starts_saturates_to_2000() {
        // 1999-06-15 00:00:00 UTC has no representation in a year-since-2000 field.
        let packed = pack(at(929_404_800));
        assert_eq!(packed, 0x0000_00cf);
        assert_eq!((packed >> 5) & 0x0f, 6, "June still packs");
    }

    #[test]
    fn a_non_request_payload_is_returned_untouched() {
        let mut source = ScriptedSource::new([Ok(vec![0x03, 0, 0, 0])]);
        assert_eq!(
            demux_interrupt(&mut source),
            Ok(vec![0x03, 0, 0, 0]),
            "a finger event is not a timestamp request"
        );
        assert!(source.answers.is_empty());
    }

    #[test]
    fn a_host_timestamp_request_before_an_announcement_is_answered_and_the_announcement_returned() {
        let real = vec![0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00];
        let mut source = ScriptedSource::new([Ok(request()), Ok(real.clone())]);

        assert_eq!(demux_interrupt(&mut source), Ok(real));
        assert_eq!(source.answers, [true], "the request was answered once");
    }

    #[test]
    fn a_host_timestamp_request_during_a_finger_wait_is_answered_and_the_finger_returned() {
        let finger = vec![0x03, 0x00, 0x00, 0x00];
        let mut source = ScriptedSource::new([Ok(request()), Ok(finger.clone())]);

        assert_eq!(demux_interrupt(&mut source), Ok(finger));
        assert_eq!(source.answers, [true]);
    }

    #[test]
    fn a_sync_failure_is_a_typed_transport_error() {
        let mut source = ScriptedSource::new([Ok(request())]);
        source.answer_error = Some(UsbError::Stall);

        assert_eq!(demux_interrupt(&mut source), Err(UsbError::Stall));
        assert!(source.answers.is_empty(), "a failed answer is not recorded");
    }

    #[test]
    fn repeated_requests_stop_at_the_bound() {
        let mut source =
            ScriptedSource::new(std::iter::repeat_with(|| Ok(request())).take(MAX_REQUESTS + 1));

        assert_eq!(
            demux_interrupt(&mut source),
            Err(UsbError::TimestampRequests)
        );
        assert_eq!(source.answers.len(), MAX_REQUESTS);
    }

    fn request() -> Vec<u8> {
        HOST_TIMESTAMP_INTERRUPT.to_le_bytes().to_vec()
    }

    struct ScriptedSource {
        reads: VecDeque<Result<Vec<u8>, UsbError>>,
        answers: Vec<bool>,
        answer_error: Option<UsbError>,
    }

    impl ScriptedSource {
        fn new(reads: impl IntoIterator<Item = Result<Vec<u8>, UsbError>>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                answers: Vec::new(),
                answer_error: None,
            }
        }
    }

    impl TimestampInterrupt for ScriptedSource {
        fn read_interrupt(&mut self) -> Result<Vec<u8>, UsbError> {
            self.reads
                .pop_front()
                .unwrap_or_else(|| Err(UsbError::Other("no scripted read".to_owned())))
        }

        fn answer_timestamp(&mut self) -> Result<(), UsbError> {
            match &self.answer_error {
                Some(error) => Err(error.clone()),
                None => {
                    self.answers.push(true);
                    Ok(())
                }
            }
        }
    }
}

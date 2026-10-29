//! The probe's finger-wait view of the host timestamp request.
//!
//! The encoding, the control request and the retry bound live in [`cv3_wire::timestamp`], the one
//! home both the command exchange and the plugin use. This module re-exports them so the probe's
//! own code keeps one import, and holds the demultiplexer for the **finger wait**, which is the one
//! read the shared command exchange does not own.
//!
//! The command path answers type-5 events inside [`cv3_wire::Exchange`]; the finger wait below does
//! the same thing over its own interrupt source.

pub use cv3_wire::timestamp::{
    HOST_TIMESTAMP_INTERRUPT, HOST_TIMESTAMP_REQUEST, HOST_TIMESTAMP_REQUEST_TYPE, MAX_REQUESTS,
    SYNC_TIMEOUT_MS, is_host_timestamp_request, pack,
};

use crate::usb::UsbError;

/// One interrupt source that can be read and answered with the host timestamp.
///
/// This is the internal seam the demultiplexing is tested through: the real transport wraps an
/// interrupt endpoint and the demux tests wrap a scripted queue.
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
    use std::time::{Duration, UNIX_EPOCH};

    fn at(seconds: u64) -> std::time::SystemTime {
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

# 13: Enrol through fprintd

**What to build:** a finger can be enrolled from the desktop settings or `fprintd-enroll`, and the print
persists across a `fprintd` restart.

**Blocked by:** 12 (session through fprintd), 06 (enrolment)

**Status:** in-progress

- [ ] `fprintd-enroll` completes an enrolment end to end, reporting up to thirteen declared stages: the
      samples the sensor accepts plus the binding confirmation, fewer when the sensor completes early
- [ ] The enrolled print survives a `fprintd` restart
- [x] The persisted print carries the enrolment id (or the sample hash used in its place) and the match
      id; an unknown payload version is rejected rather than guessed
- [x] A failed or skipped confirmation fails the enrolment and stores no print, and the driver reports
      that a template may remain on the sensor
- [x] A cancelled enrolment leaves no stored print, and says the same about the sensor

## Implementation notes

- The class declares **13** stages (`cv3_tod_enrol_stages`, from `cv3_core::bind::ENROL_STAGES`) and
  the `enroll` vfunc drives `EnrolAndBind`: up to twelve accepted samples, the `0x6E` commit, then one
  confirmation touch (`0x66`, finger, `0x2F` against the commit reply's handle). A stage is reported
  per accepted sample; a rescan is reported as an `FP_DEVICE_RETRY_GENERAL` progress error with the
  stage count unchanged. No report exceeds 13.
- The print is stored only when `PrintPayload::accepts` accepts the confirmation: the measured reply
  shape, verdict `1` and the commit reply's handle. Otherwise the enrolment fails, no print is stored,
  and the message says the template may remain on the sensor and cannot be identified or removed yet.
- On success the shim sets `fpi-type` to `FPI_PRINT_RAW` and `fpi-data` to a 30-byte `ay` GVariant
  built by `g_variant_new_fixed_array`. `scripts/check-tod-class.sh` pins that this libfprint
  round-trips that representation through `fp_print_serialize`/`fp_print_deserialize`.
- **ABI note:** libfprint 1.95 has no `FP_DEVICE_FEATURE_ENROLL`. Enrolment is advertised by a
  non-zero `nr_enroll_stages` (fprintd gates `EnrollStart` on it), so the class keeps the ticket-11
  `CAPTURE` bit only because `fp_device_constructed` asserts a non-empty mask, and probe still
  withdraws it. When ticket 14 lands, `VERIFY` replaces that placeholder.
- Cancellation cancels only the finger wait (`fpi_device_get_cancellable` on the `WAIT_FINGER`
  action); command transfers are never submitted cancellable. Ticket 15 owns the full cancel path.

## What the hardware run must confirm

- That `0x2F` with the commit handle answers `verdict 1` with the same handle **within the enrolment
  session**, and that a 30-byte print then reloads through fprintd after a restart (the payload's
  round trip is checked without hardware; the sensor round trip is not).
- That the sensor tolerates a capture immediately after the commit in this exact command order, and
  that twelve accepted samples plus the confirmation are what a real finger produces.
- That `fpi-data` set as an `ay` GVariant is what fprintd's storage writes back and `fprintd-verify`
  (ticket 14) can read.

# 13: Enrol through fprintd

**What to build:** a finger can be enrolled from the desktop settings or `fprintd-enroll`, and the print
persists across a `fprintd` restart.

**Blocked by:** 12 (session through fprintd), 06 (enrolment)

**Status:** ready-for-human

- [x] `fprintd-enroll` completes an enrolment end to end, reporting up to thirteen declared stages:
      the samples the sensor accepts plus the binding confirmation, fewer when the sensor completes
      early (measured 2026-10-29: twelve accepted stages, retries in between, confirmation, then
      `Enroll result: enroll-completed`).
- [x] The enrolled print survives a `fprintd` restart (measured: `fprintd-list` still shows
      `right-index-finger` after `systemctl restart fprintd`).
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

## Comments

Hardware 2026-10-29, after two ownership fixes:

- `cv3_tod` reached twelve accepted samples (with `enroll-retry-scan` retries in between), then the
  confirmation touch, and `fprintd-enroll` printed `Enroll result: enroll-completed`;
- `fprintd-list` showed `right-index-finger` and still showed it after `systemctl restart fprintd`.

Two bugs surfaced on hardware and are pinned by comments and the class harness:

1. `fpi_device_enroll_progress` takes ownership of the `GError` and rejects a print passed with an
   error. The retry path passed the template and cleared the error itself, aborting fprintd with
   `free(): invalid pointer`.
2. `fpi_device_get_enroll_data` returns a borrowed print (transfer none) while
   `fpi_device_enroll_complete` takes ownership (transfer full). Passing the borrowed pointer made
   completion consume the task's reference and the task free it again: SEGV in `g_object_unref`
   right after stage 13. The shim passes `g_object_ref(print)`, as libfprint's own drivers do.

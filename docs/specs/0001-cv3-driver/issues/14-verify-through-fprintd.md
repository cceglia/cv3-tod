# 14: Verify through fprintd

**What to build:** `fprintd-verify` returns a real verdict from the sensor, with the id binding active,
so anything speaking fprintd's protocol works.

**Blocked by:** 13 (enrol through fprintd), 10 (id binding)

**Status:** done

- [x] `fprintd-verify` reports a match for a print enrolled through fprintd by ticket 13
      (measured 2026-10-29: `verify-match`).
- [x] It reports no match for an unenrolled finger, and the enrolled print still verifies after a
      `fprintd` restart (measured: the left index against the right-index print gave
      `verify-no-match`; the right index still matched after `systemctl restart fprintd`).
- [x] A verification for a specific finger succeeds only for that finger (measured: the right
      index matched, the left index did not).
- [x] The driver declares only the features it implements, so clients do not offer operations that
      cannot work
- [x] A sensor that is absent or held elsewhere produces an error the client can distinguish from a
      failed match

## Implementation notes

- The class declared exactly `FP_DEVICE_FEATURE_VERIFY` at this ticket. The ticket-11 `CAPTURE`
  placeholder and the probe's `fpi_device_update_features` withdrawal are gone (ticket 20 later
  added `IDENTIFY`, giving `VERIFY|IDENTIFY`): libfprint only needs a non-empty mask,
  and VERIFY was it at this ticket. `CAPTURE`, `STORAGE`, `STORAGE_LIST`, `STORAGE_DELETE` and
  `STORAGE_CLEAR` stay undeclared, and their vfuncs stay NULL. Enrolment is still advertised by the
  stage count, because libfprint 1.95 has no `FP_DEVICE_FEATURE_ENROLL`.
- `verify` reads the print's `fpi-data` with `g_object_get`, finds the bytes with
  `g_variant_get_fixed_array` and hands pointer and length to Rust
  (`cv3_tod_verify_start`). Nothing in C reads a field of the record: `PrintPayload::decode` decides,
  and an unreadable record is a typed error, never a guess. A missing payload completes with
  `FP_DEVICE_ERROR_DATA_NOT_FOUND`, and so does an empty one; a print whose `fpi-data` is not a byte
  array, and a record that is foreign, another version or the wrong length, complete with
  `FP_DEVICE_ERROR_DATA_INVALID` — both before any transfer.
- The core runs one `Verify`: a `0x66` arm, the cancellable finger wait, then `0x2F` against the
  single template handle the record names. Only `PrintPayload::accepts` accepts the answer: the
  measured 56-byte reply, verdict `1` and the recorded handle.
- Outcomes are kept apart so fprintd can tell them apart: a match reports `FPI_MATCH_SUCCESS`, a
  no-match (verdict `0`, verdict `1` for another handle, or another verdict word) reports
  `FPI_MATCH_FAIL` with no error, a finger-wait timeout reports `FPI_MATCH_ERROR` with a
  `FP_DEVICE_RETRY_GENERAL` error (the only shape libfprint accepts with an error), a cancel reports no verdict
  and completes with libfprint's cancellation (ticket 15's behaviour), and a transport or protocol failure completes with
  `FP_DEVICE_ERROR_REMOVED`/`GENERAL`/`PROTO`. Retry errors go to the report, never to the
  completion. A reply that does not decrypt, a body the sensor never sent and a refused request stay
  device errors rather than a no-match: the driver cannot say what that answer meant.
- A success and a no-match leave the session open and usable: verify never opens or closes it. A
  `MalformedReply`, a refused request or a transport failure runs the core's best-effort teardown
  (`0x68`, `0x04`) as SPEC "Failure and recovery" requires, so there is no session to keep. A cancel
  and a finger timeout do the same; ticket 15 owns making the device usable without fprintd
  reopening it. The scripted tests therefore assert the session still held after a match, a
  no-match, a wrong handle and each payload error, and `Job::Finished` after the cases whose teardown
  ran: keeping a handle the sensor has been told to drop would be a lie.
- The finger wait is the only transfer submitted cancellable, exactly as in enrolment.

## What the hardware run must confirm

- That `fprintd-verify` reports `verify-match` for a print enrolled through ticket 13, and
  `verify-no-match` for another finger.
- That the print's `0x2F` handle still matches after a `fprintd` restart (the handle was measured to
  survive a power cycle with `cvctl`; the fprintd storage path is not measured).
- That a finger-wait timeout reaches the client as a retry rather than a device error.

## Comments

A successful verification cannot be shown under `scripts/check-tod-class.sh`: the fake holds no
session key, so it cannot fabricate the wrapped `0x2F` reply. The harness pins the class shape
(features, NULL vfuncs), the two payload errors before any frame is written, and that the record
reaches the core — the `0x66`, `0x68`, `0x04` are what the fake sees. The verdict, the binding and
the session reuse are covered by the plugin's scripted tests.

Measured on hardware 2026-10-29 with the print enrolled through ticket 13:

```text
fprintd-verify -f right-index-finger cristiano
Verifying: right-index-finger
Verify result: verify-match (done)
```

With the left index presented against that print: `Verify result: verify-no-match (done)`. After
`systemctl restart fprintd` the right index still matched. The payload read is the same `fpi-data`
the enrolment stored, so a print reloaded from fprintd's database verifies without re-enrolment.

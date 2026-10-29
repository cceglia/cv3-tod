# 05: Capture

**What to build:** `cvctl capture` arms a capture, waits for the finger, and reports what the sensor
read — the one primitive that verification and enrolment both stand on.

**Blocked by:** 03 (secure session), 04 (offline harness)

**Status:** done

- [x] `cvctl capture` arms a capture, waits for the finger event, and reports the sample hash the
      sensor returns (measured 2026-10-29: `sample hash c43e…3bd08`).
- [x] A "capture already pending" reply is reported as its own outcome, never as a capture
      (scripted `0x85` test).
- [x] A reply that carries no sample hash is reported as its own outcome rather than treated as empty
      (scripted hash-less reply test).
- [x] Waiting for a finger that never arrives ends in a distinct timeout outcome with the session
      closed (measured: `no finger event arrived within the finger timeout`, exit 8).
- [x] A transport error at any step is reported without panicking and without leaving the session open
      (scripted transport-failure tests).
- [x] The arm-wait-report flow is covered by scripted-transport tests before it is first run on
      hardware.

## Comments

Implemented in 0823682; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Scripted tests cover
arm, finger, hash, `0x85`, a hash-less reply, the finger timeout, transport failures and
cancellation, and assert the `0x68`/`0x04` teardown.

Hardware: `sudo ./target/debug/cvctl capture` (touch → sample hash; no touch → exit 8; leave a
capture armed → exit 7). The `0x66`/`0x68`/`0x04` frames were checked against the audited reference,
not against the sensor.

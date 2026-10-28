# 05: Capture

**What to build:** `cvctl capture` arms a capture, waits for the finger, and reports what the sensor
read — the one primitive that verification and enrolment both stand on.

**Blocked by:** 03 (secure session), 04 (offline harness)

**Status:** ready-for-agent

- [ ] `cvctl capture` arms a capture, waits for the finger event, and reports the sample hash the
      sensor returns
- [ ] A "capture already pending" reply is reported as its own outcome, never as a capture
- [ ] A reply that carries no sample hash is reported as its own outcome rather than treated as empty
- [ ] Waiting for a finger that never arrives ends in a distinct timeout outcome with the session
      closed
- [ ] A transport error at any step is reported without panicking and without leaving the session open
- [ ] The arm-wait-report flow is covered by scripted-transport tests before it is first run on
      hardware

# 04: Verification

**What to build:** `cvctl verify` arms a capture, waits for the finger event, asks the sensor to
match, and reports match or no-match — the first end-to-end biometric result.

**Blocked by:** 03 (secure session)

**Status:** ready-for-agent

- [ ] `cvctl verify` reports a match for a finger that is enrolled on the sensor
- [ ] It reports no match for a finger that is not enrolled
- [ ] A "capture already pending" reply is surfaced as its own outcome and never mistaken for a
      result
- [ ] Waiting for a finger that never arrives ends in a distinct timeout outcome, with the session
      left closed
- [ ] A transport error at any step is reported without panicking and without leaving the session
      open

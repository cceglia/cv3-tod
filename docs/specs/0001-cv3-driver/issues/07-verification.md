# 07: Verification

**What to build:** `cvctl verify` reads a finger and asks the sensor to match it, reporting match or
no-match against an enrolment that is already on the sensor.

**Blocked by:** 05 (capture), 06 (enrolment)

**Status:** ready-for-agent

- [ ] `cvctl verify` reports a match for a finger enrolled by ticket 06
- [ ] It reports no match for a finger that is not enrolled
- [ ] The full match reply is decoded and printed: the verdict word, the 20-byte value that follows it,
      and the reply's exact length
- [ ] The reply to a **no-match** is captured and recorded in the same detail, including whether it
      carries the enrolled finger's value at that position
- [ ] A capture timeout and a transport error produce distinct outcomes, with the session closed
- [ ] Both outcomes are covered by scripted-transport tests

# 07: Verification

**What to build:** `cvctl verify` reads a finger and asks the sensor to match it, reporting match or
no-match against an enrolment that is already on the sensor.

**Blocked by:** 05 (capture), 06 (enrolment)

**Status:** ready-for-agent

- [ ] `cvctl verify` reports a match for a finger enrolled by ticket 06
- [ ] It reports no match for a finger that is not enrolled, and a no-match reply is not expected to
      carry an id
- [ ] The 20-byte value the sensor returns alongside a match is decoded and printed verbatim, without
      assuming what it is
- [ ] A capture timeout and a transport error produce distinct outcomes, with the session closed
- [ ] Both outcomes are covered by scripted-transport tests

# 10: Id binding

**What to build:** a verification succeeds only for the finger enrolled for that print — closing the
hole where one user's finger satisfies another user's prompt, and where an altered match flag forges a
match.

**Blocked by:** 09 (binding facts), 06 (enrolment), 07 (verification)

**Status:** ready-for-agent

- [ ] After committing an enrolment, the driver asks for one confirmation touch and records the match
      id the sensor returns for it, as the thirteenth of thirteen declared stages
- [ ] Verification requires the returned match id to equal the recorded one, and fails with a distinct
      reason when the sensor reports a match but the ids differ
- [ ] A different finger enrolled on the same sensor does not satisfy verification for this print
- [ ] If the confirmation does not happen or fails, the enrolment fails and no print is stored; the
      template left on the sensor is reported as orphaned
- [ ] The stored record round-trips through the versioned payload, and an unknown payload version is
      rejected
- [ ] The limits are documented where the code lives: the confirmation cannot be proven to be the same
      finger, and the comparison does not detect a replayed reply

# 06: Cancellation and recovery

**What to build:** an interrupted capture leaves the sensor usable, and the project finally settles
the one protocol fact its two reference implementations disagree about: whether a "capture pending"
reply advances the wrap sequence.

**Blocked by:** 05 (enrolment)

**Status:** ready-for-agent

- [ ] Interrupting `cvctl` during the finger wait cancels the capture and closes the session before
      exiting
- [ ] After a cancellation, a verification in the same run succeeds — this is the behaviour that
      distinguishes the two candidate sequence rules
- [ ] The wrap-sequence rule lives in exactly one predicate, and the observed behaviour of a
      "capture pending" reply is recorded next to it
- [ ] Both readings of the rule are covered by tests, so switching the predicate is a one-line
      change
- [ ] Recovery uses only the documented escalation ladder; no code path resets the device

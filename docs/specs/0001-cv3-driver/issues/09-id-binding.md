# 09: Id binding

**What to build:** a verification succeeds only for the finger enrolled for that print — closing the
hole where one user's finger satisfies another user's prompt, and where a tampered reply can forge a
match.

**Blocked by:** 06 (enrolment), 07 (verification)

**Status:** ready-for-agent

- [ ] After committing an enrolment, the driver asks for one confirmation touch and records the match
      id the sensor returns for it
- [ ] Verification requires the returned match id to equal the recorded one, and fails with a
      distinct reason when the sensor reports a match but the ids differ
- [ ] A different finger enrolled on the same sensor does not satisfy verification for this print
- [ ] If the confirmation touch does not happen, the print is stored unbound and every verification
      of it reports that it is unbound
- [ ] The stability of the match id across separate sessions is measured and recorded; if it is
      unstable, unbound becomes the default and the limitation is written into the project's docs
- [ ] The stored record round-trips through the versioned payload, and a print with an unknown
      payload version is rejected

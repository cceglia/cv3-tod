# 10: Id binding

**What to build:** a verification succeeds only for the finger enrolled for that print — closing the
hole where one user's finger satisfies another user's prompt, and where an altered match flag forges a
match.

**Blocked by:** 09 (binding facts), 06 (enrolment), 07 (verification)

If ticket 09 returns a negative result, this ticket closes with that finding instead of being
implemented.

**Status:** ready-for-agent

- [ ] After committing, the driver asks for one confirmation touch and records the value the sensor
      returns for it
- [ ] Verification requires the returned value to equal the recorded one **and** the reply to have the
      exact structure the match command produces, so a flag flip that leaves the value untouched is not
      enough by itself
- [ ] A different finger enrolled on the same sensor does not satisfy verification for this print
- [ ] If the confirmation does not happen or fails, no print is stored, and the driver reports that a
      template may remain on the sensor and cannot be identified or removed yet
- [ ] The stored record round-trips through the versioned payload, and an unknown payload version is
      rejected
- [ ] The limits are documented where the code lives: the confirmation cannot be proven to be the same
      finger, and the comparison does not detect a replayed reply

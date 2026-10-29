# 10: Id binding

**What to build:** a verification succeeds only for the finger enrolled for that print — closing the
hole where one user's finger satisfies another user's prompt, and where an altered match flag forges a
match.

**Blocked by:** 09 (binding facts), 06 (enrolment), 07 (verification)

If ticket 09 returns a negative result, this ticket closes with that finding instead of being
implemented.

**Status:** in-progress

- [x] After committing, the driver asks for one confirmation touch and records the value the sensor
      returns for it (`Enrol` keeps the `0x6E` handle; `enroll-then-verify` prints the payload).
- [ ] Verification requires the returned value to equal the recorded one **and** the reply to have the
      exact structure the match command produces, so a flag flip that leaves the value untouched is not
      enough by itself
- [x] A different finger enrolled on the same sensor does not satisfy verification for this print
      (measured: handle `0x002f1a08` matched by finger B, `0x007069a9` by finger A only).
- [ ] If the confirmation does not happen or fails, no print is stored, and the driver reports that a
      template may remain on the sensor and cannot be identified or removed yet
- [x] The stored record round-trips through the versioned payload, and an unknown payload version is
      rejected.
- [x] The limits are documented where the code lives (`crates/cv3-core/src/print.rs`).

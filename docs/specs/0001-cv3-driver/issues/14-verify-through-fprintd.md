# 14: Verify through fprintd

**What to build:** `fprintd-verify` returns a real verdict from the sensor, with the id binding active,
so anything speaking fprintd's protocol works.

**Blocked by:** 13 (enrol through fprintd), 10 (id binding)

**Status:** ready-for-agent

- [ ] `fprintd-verify` reports a match for a print enrolled through fprintd by ticket 13
- [ ] It reports no match for an unenrolled finger, and the enrolled print still verifies after a
      `fprintd` restart
- [ ] A verification for a specific finger succeeds only for that finger
- [ ] The driver declares only the features it implements, so clients do not offer operations that
      cannot work
- [ ] A sensor that is absent or held elsewhere produces an error the client can distinguish from a
      failed match

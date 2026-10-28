# 10: Verify through fprintd

**What to build:** `fprintd-verify` returns a real verdict from the sensor, with the id binding
active, so the reader works for anything that speaks fprintd's protocol.

**Blocked by:** 09 (plugin skeleton), 07 (id binding)

**Status:** ready-for-agent

- [ ] `fprintd-verify` reports a match for the enrolled finger and no match for another finger
- [ ] A verification for a specific finger succeeds only for that finger
- [ ] The driver declares only the features it implements, so clients do not offer operations that
      cannot work
- [ ] A sensor that is absent or held elsewhere produces an error the client can distinguish from a
      failed match

# 18: Delete and clear

**What to build:** deleting a fingerprint removes it from the sensor, so a revoked finger genuinely
stops working, and clearing empties the store.

**Blocked by:** 17 (device-stored listing and identification)

**Status:** ready-for-agent

- [ ] Deleting a fingerprint removes it from the sensor, and that finger no longer matches afterwards
- [ ] Clearing removes every template, and no enrolled finger matches afterwards
- [ ] If no delete command is found, deletion and clearing are reported as unsupported, the print stays
      visible, and the ticket records that outcome; deletion is never emulated by overwriting
- [ ] If ticket 16 closed as undecoded, this ticket records that outcome and its criteria are
      explicitly abandoned rather than left unmet
- [ ] A failure partway through clearing leaves the store in a state `fprintd-list` reports accurately

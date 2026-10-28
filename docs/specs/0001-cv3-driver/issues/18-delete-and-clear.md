# 18: Delete and clear

**What to build:** deleting a fingerprint removes it from the sensor, so a revoked finger genuinely
stops working, and clearing empties the store.

**Blocked by:** 17 (device-stored listing), 21 (delete and clear discovery)

If ticket 21 finds no command, this ticket reports the operation as unsupported and closes with that
finding.

**Status:** ready-for-agent

- [ ] Deleting a fingerprint removes it from the sensor, and that finger no longer matches afterwards
- [ ] Clearing removes every template, and no enrolled finger matches afterwards
- [ ] If no command exists, deletion and clearing are reported as unsupported and the print stays
      visible; deletion is never emulated by overwriting
- [ ] A failure partway through clearing leaves the store in a state `fprintd-list` reports accurately

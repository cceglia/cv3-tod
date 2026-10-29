# 18: Delete and clear

**What to build:** deleting a fingerprint removes it from the sensor, so a revoked finger genuinely
stops working, and clearing empties the store.

**Blocked by:** 17 (device-stored listing), 21 (delete and clear discovery)

If ticket 21 finds no command, this ticket reports the operation as unsupported and closes with that
finding.

**Status:** done

- [ ] Deleting a fingerprint removes it from the sensor, and that finger no longer matches afterwards
- [ ] Clearing removes every template, and no enrolled finger matches afterwards
- [x] If no command exists, deletion and clearing are reported as unsupported and the print stays
      visible; deletion is never emulated by overwriting. The driver declares no storage feature and
      has no delete/clear vfunc; fprintd keeps host-stored prints and no sensor template is touched.
      Ticket 21 found no wire command (see its Outcome).
- [ ] A failure partway through clearing leaves the store in a state `fprintd-list` reports accurately

## Outcome: unsupported

Ticket 21 found no delete or clear wire command, and ticket 16 did not decode the inventory, so
there is no template-to-print map and no way to address a stored template. The driver declares no
`STORAGE_DELETE`/`STORAGE_CLEAR` feature and implements no delete or clear vfunc. Deleting a
fingerprint removes fprintd's host record; the sensor's template is not touched and the driver says
so rather than pretending the finger is revoked. Emulating deletion by overwriting is not done.

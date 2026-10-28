# 14: Device-stored prints

**What to build:** listing, deleting and clearing operate on the sensor's own store, so a deleted
fingerprint genuinely stops working.

**Blocked by:** 13 (inventory decoding), 11 (enrol through fprintd)

**Status:** ready-for-agent

- [ ] `fprintd-list` shows the templates that exist on the sensor
- [ ] Deleting a fingerprint removes it from the sensor, and that finger no longer matches afterwards
- [ ] Clearing removes every template, and no enrolled finger matches afterwards
- [ ] If no delete command can be found, deletion is reported as unsupported and the print stays
      visible; it is never emulated
- [ ] The host-stored fallback remains selectable, and which model is active is observable from the
      features the driver declares

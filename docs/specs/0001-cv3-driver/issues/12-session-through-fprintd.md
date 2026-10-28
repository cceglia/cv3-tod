# 12: Session through fprintd

**What to build:** opening and closing the sensor through `fprintd` performs the handshake and the
session teardown, so the plugin is wired end to end before any biometric behaviour exists.

**Blocked by:** 11 (plugin loads)

**Status:** ready-for-agent

- [ ] Claiming the device through `fprintd` opens the secure session and releasing it closes the
      session cleanly
- [ ] A second open after a failed open succeeds instead of reporting "already open"
- [ ] No session handle is left on the sensor after a failed open
- [ ] `fprintd` does not hang when the sensor is absent during open

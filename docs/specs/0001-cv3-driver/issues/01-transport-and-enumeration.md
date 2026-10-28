# 01: Transport and enumeration

**What to build:** `cvctl` finds the ControlVault 3 sensor, opens it, inspects its interface and
endpoints, and releases it cleanly — the walking skeleton that proves the pure-Rust USB path before
any protocol work exists.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `cvctl devices` prints the sensor's vendor and product, bus and port when it is present
- [ ] It refuses with a distinct "busy" message, without disturbing anything, when another process
      (such as `fprintd`) holds the sensor
- [ ] It reports a clear "not found" and exits non-zero when the sensor is absent
- [ ] It claims the interface, reads the endpoint layout, and releases both on the success path, on
      error and on interrupt
- [ ] No code path resets the USB device or writes the port's `disable` knob

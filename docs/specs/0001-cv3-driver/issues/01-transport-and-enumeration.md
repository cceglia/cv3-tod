# 01: Transport and enumeration

**What to build:** `cvctl` finds the ControlVault 3 sensor, opens it, inspects its interface and
endpoints, and releases it cleanly — the walking skeleton that proves the pure-Rust USB path before
any protocol work exists.

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [ ] `cvctl devices` prints the sensor's vendor and product, bus and port when it is present
- [ ] It refuses with a distinct "busy" message, without disturbing anything, when another process
      (such as `fprintd`) holds the sensor
- [ ] It reports a clear "not found" and exits non-zero when the sensor is absent
- [ ] It claims the interface, reads the endpoint layout, and releases both on the success path, on
      error, and on a catchable signal
- [ ] An announced non-zero reply body is always read before the next command, and a zero-length
      announcement performs no read — both covered by tests
- [ ] No code path resets the USB device or writes the port's `disable` knob

## Comments

Implemented in 5624528; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Offline validation
passes: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --all -- --check`, `./scripts/check-core.sh`.

Hardware acceptance is still open, so the boxes stay unticked: print the sensor when present, refuse
when `fprintd` holds interface 0, exit non-zero when absent, and release the claim on a signal. Run
as root: `sudo ./target/debug/cvctl devices` (present, absent, and with `fprintd` holding the
device), then interrupt a long run and rerun `devices`.

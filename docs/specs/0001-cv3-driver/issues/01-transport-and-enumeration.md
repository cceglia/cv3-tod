# 01: Transport and enumeration

**What to build:** `cvctl` finds the ControlVault 3 sensor, opens it, inspects its interface and
endpoints, and releases it cleanly — the walking skeleton that proves the pure-Rust USB path before
any protocol work exists.

**Blocked by:** None (can start immediately)

**Status:** done

- [x] `cvctl devices` prints the sensor's vendor and product, bus and port when it is present
      (measured 2026-10-29: `vendor 0a5c product 5843 bus 3 port 8`).
- [x] It refuses with a distinct "busy" message, without disturbing anything, when another process
      (such as `fprintd`) holds the sensor (measured: exit 3 and `interface 0 is already claimed`
      while a verify was waiting).
- [x] It reports a clear "not found" and exits non-zero when the sensor is absent (measured with the
      device deauthorized: `sensor 0a5c:5843 not found`, exit 2; it came back after reauthorizing).
- [x] It claims the interface, reads the endpoint layout, and releases both on the success path, on
      error, and on a catchable signal (measured: `devices` twice around the busy and absent cases;
      Ctrl+C during `capture` gave `capture cancelled` and the next `devices` succeeded).
- [x] An announced non-zero reply body is always read before the next command, and a zero-length
      announcement performs no read — both covered by tests
      (`a_non_zero_announcement_reads_exactly_its_body`,
      `a_zero_length_announcement_performs_no_bulk_read`).
- [x] No code path resets the USB device or writes the port's `disable` knob (grep of the probe
      sources: neither call exists).

## Comments

Implemented in 5624528; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Offline validation
passes: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --all -- --check`, `./scripts/check-core.sh`.

Hardware acceptance is still open, so the boxes stay unticked: print the sensor when present, refuse
when `fprintd` holds interface 0, exit non-zero when absent, and release the claim on a signal. Run
as root: `sudo ./target/debug/cvctl devices` (present, absent, and with `fprintd` holding the
device), then interrupt a long run and rerun `devices`.

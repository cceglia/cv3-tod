# 11: Plugin loads

**What to build:** the sensor appears to `fprintd` as a reader, driven by the same core the probe uses,
through the C shim — enumeration only, no session yet.

**Blocked by:** 03 (secure session)

**Status:** in-progress

- [x] The shim builds against the distribution's `libfprint` TOD headers and links the versioned
      symbols; the build fails loudly rather than binding the legacy compatibility thunk
      (`scripts/build-plugin.sh` + `scripts/check-tod-link.sh`; every import checked with `readelf`).
- [ ] `fprintd` reports the reader
- [x] The shim contains no parsing, no length arithmetic and no cryptography; it forwards to the core
      and performs transfers (at this milestone it is GObject plumbing only and performs none).
- [x] The plugin is installed and removed by adding or deleting a single shared object, with no change
      to `libfprint` or `fprintd` configuration (`scripts/install-plugin.sh`, `uninstall-plugin.sh`;
      exercised against a temporary TOD directory).
- [x] A failed probe leaves `fprintd` running and the device available to the next attempt: this
      milestone's probe performs no USB transfer, so it has no failure path that can wedge the
      sensor or the daemon.

## Comments

Implemented in the third workspace crate, `crates/cv3-tod`: a Rust `cdylib` with a C shim compiled by
`build.rs`. The exported entry point is a Rust trampoline to the shim's `GType` getter because rustc's
`cdylib` version script exports only Rust-declared symbols. libfprint refuses to construct a device
class with no feature at all, so the class declares `CAPTURE` and the probe withdraws it with
`fpi_device_update_features` before completing: the reader is listed and no operation is offered.
Enumeration verified without root by pointing `FP_TOD_DRIVERS_DIR` at the built object
(libfprint reports one device, driver `cv3`, features 0). Installing under the real TOD directory and
`fprintd-list` need root and are the remaining box.

# 11: Plugin loads

**What to build:** the sensor appears to `fprintd` as a reader, driven by the same core the probe uses,
through the C shim — enumeration only, no session yet.

**Blocked by:** 03 (secure session)

**Status:** in-progress

**Manual acceptance (needs root):** with the plugin in the real TOD directory and `fprintd`
restarted, `fprintd-list "$USER"` reports the `cv3` reader *and* `fprintd-enroll "$USER"` fails
cleanly with `NOT_SUPPORTED` while `fprintd` stays alive. A daemon that crashes or hangs on Claim
fails the ticket; a missing reader alone is not the whole check.

- [x] The shim builds against the distribution's `libfprint` TOD headers and links the versioned
      symbols; the build fails loudly rather than binding the legacy compatibility thunk
      (`scripts/build-plugin.sh` + `scripts/check-tod-link.sh`; every `fpi_*` import checked with
      `readelf`).
- [ ] `fprintd` reports the reader, and a manual `fprintd-enroll` fails cleanly and leaves `fprintd`
      alive.
- [x] The shim contains no parsing, no length arithmetic and no cryptography; it forwards nothing to
      the core yet and performs no transfers (GObject plumbing only at this milestone).
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
`fpi_device_update_features` before completing: the device advertises no feature after probe.

libfprint 1.95 calls `FpDeviceClass.open` and `.close` through the class pointer without a NULL
check (`fp_device_open` and `fp_device_close`), and `.enroll` the same way once a template print is
supplied. With no bodies there the Claim path dereferenced NULL inside `fprintd`, which runs as
root. The shim now sets all three: `open` fails with `FP_DEVICE_ERROR_NOT_SUPPORTED` (Claim reports
an error and the daemon and the listed reader survive), `close` completes with no error, and
`enroll` fails the same way as defence in depth. `verify`, `capture`, `identify`, `list`, `delete`
and `clear_storage` stay NULL: libfprint refuses each one unless the matching feature is set, and
the probe withdraws every feature; for all of them but `clear_storage` it also refuses a NULL
pointer. The reader is therefore listed but cannot be claimed or opened until ticket 12.

Verified without root by loading the built object with `g_module_open`, resolving
`fpi_tod_shared_driver_get_type` and reading the class: `open`, `close` and `enroll` are non-NULL.
Pointing `FP_TOD_DRIVERS_DIR` at that object, libfprint enumerates one device (driver `cv3`,
features 0) and `fp_device_open` returns `FP_DEVICE_ERROR_NOT_SUPPORTED` from the stub; the same
harness against the pre-fix object segfaults in that call. Installing under the real TOD directory,
`fprintd-list` and `fprintd-enroll` need root and are the remaining box.

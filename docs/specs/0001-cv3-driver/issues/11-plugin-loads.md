# 11: Plugin loads

**What to build:** the sensor appears to `fprintd` as a reader through the C shim — enumeration only,
with no session yet and nothing forwarded to the core. **Superseded for behaviour by tickets 12–20**;
this ticket records the load milestone and its failure path as it was then.

**Blocked by:** 03 (secure session)

**Status:** ready-for-human

**Manual acceptance (needs root):** with the plugin in the real TOD directory and `fprintd`
restarted, all of these hold:

1. `fprintd-list "$USER"` lists the reader as `Dell/Broadcom ControlVault 3`. That is the device
   name; `fprintd-list` never prints the driver id `cv3`.
2. `fprintd-enroll "$USER"` exits non-zero and prints, after its `Using device …` line:

   ```console
   failed to claim device: GDBus.Error:net.reactivated.Fprint.Error.Internal: Open failed with error: cv3: opening the sensor needs the session (ticket 12)
   ```

   `fprintd` 1.94 maps every open failure to `net.reactivated.Fprint.Error.Internal`, so the
   `NOT_SUPPORTED` libfprint reports does not reach the client under that name. A clean failure and
   a crash therefore look different in the rest of the transcript, not in that word.
3. The `fprintd` `MainPID` is unchanged across the attempt and `fprintd` is still running:
   `systemctl show -p MainPID --value fprintd` prints the same number before and after, and
   `systemctl is-active fprintd` still prints `active`.
4. A SECOND `fprintd-enroll "$USER"` prints the same open error, not "Device is already open": the
   failed open released the GUsb handle libfprint opened for it.

A daemon that crashes, exits, changes PID, or refuses the second attempt fails the ticket; a missing
reader alone is not the whole check.

- [x] The shim builds against the distribution's `libfprint` TOD headers and links the versioned
      symbols; the build fails loudly rather than binding the legacy compatibility thunk
      (`scripts/build-plugin.sh` + `scripts/check-tod-link.sh`; every `fpi_*` import checked with
      `readelf`).
- [x] `fprintd` lists the reader as `Dell/Broadcom ControlVault 3`, and both `fprintd-enroll`
      attempts fail as stated above while `fprintd` keeps its PID (measured 2026-10-29).
- [x] The shim contains no parsing, no length arithmetic and no cryptography; it forwards nothing to
      the core yet and performs no transfers (GObject plumbing only at this milestone).
- [x] The plugin is installed and removed by adding or deleting a single shared object, with no change
      to `libfprint` or `fprintd` configuration (`scripts/install-plugin.sh`, `uninstall-plugin.sh`;
      exercised against a temporary TOD directory).
- [x] A failed Claim leaves the handle free and the daemon up: `open` releases the GUsb device
      libfprint opened before failing, so the next Claim reaches the driver instead of "Device is
      already open" (`scripts/check-tod-class.sh`).

## Comments

Implemented in the third workspace crate, `crates/cv3-tod`: a Rust `cdylib` with a C shim compiled
by `build.rs`. The exported entry point is a Rust trampoline to the shim's `GType` getter because
rustc's `cdylib` version script exports only Rust-declared symbols. libfprint refuses to construct a
device class with no feature at all, so the class declares `CAPTURE` and the probe withdraws it with
`fpi_device_update_features` before completing: the device advertises no feature after probe.

libfprint 1.95 calls `FpDeviceClass.open` and `.close` through the class pointer without a NULL
check (`fp_device_open` and `fp_device_close`), and `.enroll` the same way once a template print is
supplied. With no bodies there the Claim path dereferenced NULL inside `fprintd`, which runs as
root. The shim sets all three: `open` fails with `FP_DEVICE_ERROR_NOT_SUPPORTED` (Claim reports an
error; the daemon and the listed reader survive), `close` completes with no error, and `enroll`
fails the same way as defence in depth. The other operations stay NULL: they belong to later
tickets, and the probe advertises no feature.

`fp_device_open` calls `g_usb_device_open` *before* the driver's open vfunc, and
`fpi_device_open_complete()` does not close the handle — only `fpi_device_close_complete()` does.
`fprintd` does not close a device whose open failed, so an open vfunc that only returned an error
left the sensor open in the root daemon: the next Claim failed with "Device is already open", not
with our error. `open` now releases the GUsb device (`fpi_device_get_usb_device()` then
`g_usb_device_close()`) before completing with the error. Nothing else is held: this milestone claims
no interface and starts no transfer, so there is nothing else to undo, and a second close is
harmless because gusb reports it as not open.

Checked without root by `scripts/check-tod-class.sh`, run by `scripts/build-plugin.sh` and therefore
by CI. It `g_module_open`s the built object, reads the live class (identity, id table, and
`open`/`close`/`enroll` non-NULL), then, under an `LD_PRELOAD` fake for `g_usb_device_open` and
`g_usb_device_close`, calls `fp_device_open_sync` twice: both report
`FP_DEVICE_ERROR_NOT_SUPPORTED`, neither says "already open", and two `fp_device_close_sync` calls
return safely. Against the pre-fix object the second open fails with GUsb's
`G_USB_DEVICE_ERROR_ALREADY_OPEN`, so the harness pins the behaviour rather than the source text.
Installing under the real TOD directory and running `fprintd-list`/`fprintd-enroll` as root is the
remaining manual box.

Measured on hardware 2026-10-29 with the plugin at
`/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod-1-cv3.so`:

```text
found 1 devices
Device at /net/reactivated/Fprint/Device/0
User cristiano has no fingers enrolled for Dell/Broadcom ControlVault 3.
Using device /net/reactivated/Fprint/Device/0
failed to claim device: GDBus.Error:net.reactivated.Fprint.Error.Internal: Open failed with error: cv3: opening the sensor needs the session (ticket 12)
```

`MainPID` was `153178` and `active` before and after both attempts, the two attempts printed the
same open error (never "already open"), and `fprintd-list` kept reporting the reader. All boxes met.

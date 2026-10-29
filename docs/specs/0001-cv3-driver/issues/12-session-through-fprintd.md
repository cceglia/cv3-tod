# 12: Session through fprintd

**What to build:** opening and closing the sensor through `fprintd` performs the handshake and the
session teardown, so the plugin is wired end to end before any biometric behaviour exists.

**Blocked by:** 11 (plugin loads)

**Status:** in-progress

- [ ] Claiming the device through `fprintd` opens the secure session and releasing it closes the
      session cleanly
- [x] A second open after a failed open succeeds instead of reporting "already open"
- [ ] No session handle is left on the sensor after a failed open
- [ ] `fprintd` does not hang when the sensor is absent during open

## Comments

Implemented as a `Cv3Tod` per device: an opaque Rust object the shim creates on open, feeds one
transfer result at a time, and destroys on close or a failed open. The C shim contains no parsing,
length arithmetic, cryptography or session state; it performs the transfer the Rust action asks for
with `fpi_usb_transfer_fill_*_full`/`fpi_usb_transfer_submit` and returns the actual length and a
small GError classification.

The out/interrupt/bulk-in sequencing, announcement parsing and the type-5 host-timestamp answer moved
to a new I/O-free crate, `crates/cv3-wire`: `Exchange::next_transfer()` / `on_io_result()` /
`outcome()`. The probe's blocking `Exchange` is now a thin adapter over it and keeps every existing
behaviour and test; its real transport no longer demultiplexes timestamp requests itself.

Open runs `Handshake::keeping_handle` then the wrapped `OpenSession` from `cv3-core`, so a failure
after the handle is learned sends the plain `0x04` before reporting the error; nothing needs
cancelling because no capture exists yet. The finish kind selects `FP_DEVICE_ERROR_*`: protocol
refusals are `PROTO`, a busy device `BUSY`, and a transport failure classified as `Disconnected`
(including `G_USB_DEVICE_ERROR_NO_DEVICE`) is `REMOVED`. The failure path releases interface 0,
closes the GUsb handle libfprint opened, and destroys the Rust state, so the next Claim is not
refused as "already open". Close sends `0x04` when a session is open, then releases the interface
and completes successfully even if that transfer failed (logged); `fpi_device_close_complete` closes
the GUsb handle.

Timeouts come from `cv3_core::proto::timeout`: 5 s for an OUT, 60 s for the announcement and body,
3 s for a teardown frame, 1 s for the host timestamp control request. Command transfers pass a NULL
`GCancellable`; cancellation is ticket 15's.

Verified automatically:

- `crates/cv3-wire` tests: reply with body, empty reply, short announcement, over-long body,
  body-length mismatch, timeout/disconnect at OUT, announcement and body, teardown vs command
  timeouts, timestamp request answered then the real announcement, timestamp answer failure, retry
  bound, finish idempotence.
- `crates/cv3-tod` `plugin` tests: successful open (0x23, 0x24, 0x02), failed 0x24 followed by
  the 0x04 release and `PROTO`, failed wrapped open followed by 0x04, second open after a failed
  open, close sends 0x04 and succeeds, a failed close transfer still succeeds with a logged
  message, transport failure at each stage, `Disconnected`→`REMOVED`, `Busy`→`BUSY`, a timestamp
  request during the handshake, and a transfer with no operation.
- `scripts/check-tod-class.sh` (run by `scripts/build-plugin.sh`): loads the real object, then under
  a linked fake for gusb and `fpi_usb_transfer_submit` drives a first Claim refused at 0x24 (three
  frames `0x23, 0x24, 0x04`, interface and GUsb handle released), a second Claim that completes
  (`0x23, 0x24, 0x02`), a Release that sends `0x04` and succeeds, a Release whose `0x04` transfer
  fails but which still completes successfully (the failure is logged), and a Claim whose sensor
  leaves the bus, which completes with `FP_DEVICE_ERROR_REMOVED`.

Still manual on hardware (the boxes above stay unticked): a real `fprintd` Claim against the
sensor, confirmation from the sensor side that a failed open left no handle, and the absent-sensor
case. The absent sensor never reaches the vfunc because libfprint needs the USB device to construct
it; the vanishing-device path is covered by the fake above.

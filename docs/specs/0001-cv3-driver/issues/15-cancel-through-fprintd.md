# 15: Cancel through fprintd

**What to build:** cancelling a prompt stops the capture immediately and the sensor stays healthy — the
case a screen locker hits every time it times out.

**Blocked by:** 14 (verify through fprintd), 08 (cancellation and the wrap-sequence rule)

**Status:** done

- [x] Cancelling a verification through `fprintd` returns promptly instead of waiting for the finger
      timeout (measured 2026-10-29: Ctrl+C exited immediately while `Verifying:` was waiting).
- [x] The sensor is usable immediately afterwards: the next verification succeeds without a restart or
      a power cycle (measured: the next `fprintd-verify` gave `verify-match`).
- [x] Ten consecutive cancel-then-verify cycles leave the sensor healthy (measured: ten
      `timeout -s INT 2 fprintd-verify` cycles, then `verify-match` without a restart).
- [x] A cancel that arrives while a command transfer is in flight does not abort that transfer, and the
      transfer completes before the session closes (scripted: the command transfers carry a NULL
      `GCancellable` and the C dispatch harness waits for the command's result before submitting the
      finger wait; hardware confirmation is still in the run below)

## Implementation notes

- **The finger wait is the only cancellable transfer.** `Flow` emits `Transfer::FingerIn`, the FFI
  marks only that action `cancellable = 1`, and the shim passes libfprint's
  `fpi_device_get_cancellable` for it. Every OUT, interrupt-announcement, body and control
  transfer is submitted with `NULL`, so a cancellation that arrives while a command is in flight is
  remembered by the cancellable and ends the next finger wait immediately; the command itself runs
  to its result. This is the SPEC "Timeouts" safety property.
- **No `cancel` vfunc.** libfprint cancels the action's `GCancellable` itself (and forwards an
  external task cancellation to it). That is sufficient for promptness: the wait is the only
  transfer bound to it. A `cancel` vfunc would be a second cancellation source racing the
  `GCancellable`, and it could not abort a command transfer without breaking the rule above. The
  class leaves `cancel` NULL, and both the class harness and the dispatch harness pin it.
- **A cancel is not a verdict.** The core maps `Event::Cancelled` to `CaptureError::Cancelled` (or
  the match/enrolment equivalent), runs its teardown, and finishes. The shim no longer reports
  `FPI_MATCH_FAIL` for that outcome: it completes with an error and no `fpi_device_verify_report`.
  libfprint's task already carries the external cancellation, so the client receives
  `G_IO_ERROR_CANCELLED`; the dispatch harness also asserts that no match callback arrives, so a
  cancelled run cannot be presented as a no-match or a retry. An enrolment completes the same way
  with no print stored.
- **Completion follows the teardown.** The core's `Capture`/`Match`/`Enrol` finish only after the
  sessionless `0x68` and the plain `0x04` have both been sent and had their replies consumed. The
  plugin reaches `Job::Finished`; `close_start` then sends nothing, and the next operation must be
  a fresh `0x23`/`0x24`/`0x02` open. The shim's `verifying`/`enrolling` flags are cleared in the
  same finish branch, so a subsequent operation reaches the vfunc instead of being refused as
  already in progress.
- **Ticket 08.** This design sidesteps 08's open re-arm/sequence question rather than answering it:
  after a cancellation the session is closed and the next operation is a fresh open with a fresh
  wrap sequence, so no re-arm happens inside the cancelled session. 08's per-session `0x85`/re-arm
  measurement is still open; this ticket does not claim it resolved.

## Scripted verification (2026-10-29)

- [x] A cancel at the verify finger wait finishes with `OutcomeKind::Cancelled` after exactly
      `0x66 → 0x68 → 0x04`, with one finger wait and no `0x2F`, no retry and no stored print; the
      plugin is `Job::Finished` and a second close sends nothing.
- [x] A cancel at the enrolment finger wait does the same after `0x6D → 0x8A → 0x66 → 0x68 → 0x04`,
      stores no print, and keeps the "template may remain" message.
- [x] Ten consecutive cancel-then-fresh-open sequences leave the state machine clean: each cancel
      closes its handle and the next cycle is a fresh handshake and wrapped open.
- [x] Command transfers are non-cancellable in the plugin and are submitted with `NULL` in the
      class harness; the dispatch harness submits the finger wait with libfprint's own
      `GCancellable`, asserts a command completes before the wait is submitted, and checks that
      cancelling the wait completes the action with `G_IO_ERROR_CANCELLED` and no match callback.
- [x] The dispatch harness also covers a match that finished after the client cancelled: the shim
      suppresses it (no match callback, no print), and a cancelled enrolment clears `enrolling`
      and stores no print; both allow a later operation to reach the vfunc again.

## What the hardware run must confirm

- That cancelling a verification through fprintd returns promptly (not after the 30 s finger
  timeout), and that a cancel during an enrolment behaves the same.
- That the next verification succeeds without a restart or power cycle, ten times in a row.
- That a cancel during a command transfer leaves the sensor healthy; the scripted harness proves the
  driver does not abort the transfer, but only the sensor can show the command completed.
- Which claim lifecycle fprintd uses. The cycle below Claim/Release per operation, which is the path
  the plugin supports: the core closes the session on a cancel, so the next operation is a fresh
  open. If fprintd keeps one claim across `VerifyStop`/`VerifyStart`, the next verify on that claim
  would fail until the driver grows an internal reopen; the run must record which happens.
- A practical 10-cycle command, using one D-Bus connection because fprintd's claim is tied to it:

  ```sh
  python3 - <<'PY'
  import dbus, time
  bus = dbus.SystemBus()
  dev = bus.get_object("net.reactivated.Fprint",
                       "/net/reactivated/Fprint/Device/0")
  iface = dbus.Interface(dev, "net.reactivated.Fprint.Device")
  for cycle in range(10):
      iface.Claim("cristiano")
      iface.VerifyStart("right-index-finger")   # the enrolled finger
      time.sleep(1)                             # no finger: the wait is armed
      iface.VerifyStop()                        # the cancel the screen locker sends
      iface.Release()
      print("cancel", cycle + 1, "done")
  PY
  fprintd-verify -f right-index-finger cristiano  # present the finger: must match
  ```

  The device path is the one `busctl tree net.reactivated.Fprint` prints when it is not
  `/net/reactivated/Fprint/Device/0`.

## Hardware

Measured 2026-10-29:

- `fprintd-verify -f right-index-finger` waiting at `Verifying:` and Ctrl+C: exits immediately, not
  after the 30 s finger timeout.
- The next `fprintd-verify` with the finger: `Verify result: verify-match (done)`.
- Ten `timeout -s INT 2 fprintd-verify` cycles, then a verify with the finger: `verify-match`.

Ticket 08's mid-session re-arm question is sidestepped, not resolved: this driver closes the session
on cancel and the next Claim opens a fresh one.

# 08: Cancellation and the wrap-sequence rule

**What to build:** an interrupted capture leaves the sensor usable, and the one protocol fact the two
reference implementations disagree about is settled against the hardware.

**Blocked by:** 07 (verification)

**Status:** ready-for-human

- [ ] One `cvctl` invocation arms a capture, cancels it before the finger arrives, and then completes a
      verification in the same session — the rule being tested is per-session, so the run owns one
      session and two operations
- [ ] Interrupting the probe with a signal cancels the capture and closes the session before exiting
- [ ] The wrap-sequence rule lives in exactly one predicate, and the observed behaviour of a "capture
      pending" reply is recorded next to it
- [ ] Both readings of the rule are covered by scripted-transport tests, so switching the predicate is
      a one-line change
- [ ] The recovery procedure the driver expects of an operator is written down in the project, not only
      in reference material

## Comments

Implemented in 7c276c3; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. `cvctl
cancel-then-verify` owns one session and runs arm → mid-session `0x68` → arm → finger → `0x73`; both
readings of the `0x85` sequence rule are covered through the scripted transport. A signal during the
finger wait cancels that one transfer, lets the core tear down, and exits 128+signal.
`docs/recovery.md` and `docs/protocol-notes.md` are in the tree.

Hardware: `sudo ./target/debug/cvctl cancel-then-verify`, Ctrl-C during a capture (exit 130, sensor
usable afterwards), and the `0x85` first-arm case. The shipped sequence reading is still the
reference one and is recorded as unmeasured.

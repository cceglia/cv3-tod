# 08: Cancellation and the wrap-sequence rule

**What to build:** an interrupted capture leaves the sensor usable, and the one protocol fact the two
reference implementations disagree about is settled against the hardware.

**Blocked by:** 07 (verification)

**Status:** ready-for-agent

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

# 09: Binding facts

**What to build:** the evidence the binding design rests on, measured rather than assumed — or a finding
that the design cannot work as written.

**Blocked by:** 06 (enrolment), 07 (verification)

**Status:** done

Time box: **three hardware sessions or one calendar week, whichever comes first.** Reaching it without
an answer is a result: record what was observed and stop.

- [x] A capture and a match immediately after a commit are demonstrated to work on hardware:
      `enroll-then-verify` committed `0x007069a9` and the confirmation touch matched it.
- [x] The value returned with a match is compared with the enrolment id from `0x6C`: different.
      The match reply's `(0,4,…)` entry is the commit reply's handle (`0x00f2361f`), not the 20-byte
      enrolment id.
- [x] The handle is stable across a reboot (same handle, `verdict 1`). Whether it is per-finger or
      per-template still needs the same finger enrolled twice.
- [x] The no-match reply is `(0,4,0)(0,4,0)` plus the token: no 20-byte value at `+32`, and no
      handle, so a flag flip cannot reuse an id.
- [x] Whether a second enrolment of a different finger produces a different value is recorded: finger
      A `0x007069a9`, finger B `0x002f1a08`.
- [x] The findings are written into the project's own protocol notes, not only next to the reference
      implementation, including the failed hypotheses.
- [x] A plain recommendation follows: bind by this value, or abandon the binding design and say what the
      driver can honestly claim instead. The value is a per-template handle, stable across reboots and
      not satisfied by another finger, so the driver binds by it (ticket 10).

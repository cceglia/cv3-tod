# 09: Binding facts

**What to build:** the evidence the binding design rests on, measured rather than assumed — or a finding
that the design cannot work as written.

**Blocked by:** 06 (enrolment), 07 (verification)

**Status:** ready-for-human

Time box: **three hardware sessions or one calendar week, whichever comes first.** Reaching it without
an answer is a result: record what was observed and stop.

- [ ] A capture and a match immediately after a commit are demonstrated to work, or to fail, on hardware
      — the reference implementation never does this
- [ ] The value returned with a match is compared with the enrolment id from `0x6C`: equal, or
      different? The reference comment claims different and also claims stability; both are tested
- [ ] The value is measured across several sessions and at least one reboot: is it stable, and is it
      per-finger or per-template? Enrolling the **same** finger twice distinguishes those two
- [ ] The reply to a no-match is measured: does it carry a 20-byte value, and does it equal the
      enrolled finger's one? A flag flip is only detectable if it does not
- [ ] Whether a second enrolment of a different finger produces a different value is recorded
- [ ] The findings are written into the project's own protocol notes, not only next to the reference
      implementation, including the failed hypotheses
- [ ] A plain recommendation follows: bind by this value, or abandon the binding design and say what the
      driver can honestly claim instead. A negative result closes ticket 10 rather than unblocking it

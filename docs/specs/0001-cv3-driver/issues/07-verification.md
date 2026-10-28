# 07: Verification

**What to build:** `cvctl verify` reads a finger and asks the sensor to match it, reporting match or
no-match against an enrolment that is already on the sensor.

**Blocked by:** 05 (capture), 06 (enrolment)

**Status:** ready-for-human

- [ ] `cvctl verify` reports a match for a finger enrolled by ticket 06
- [ ] It reports no match for a finger that is not enrolled
- [ ] The full match reply is decoded and printed: the verdict word, the 20-byte value that follows it,
      and the reply's exact length
- [ ] The reply to a **no-match** is captured and recorded in the same detail, including whether it
      carries the enrolled finger's value at that position
- [ ] A capture timeout and a transport error produce distinct outcomes, with the session closed
- [ ] Both outcomes are covered by scripted-transport tests

## Comments

Implemented in 3fa807b; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2, including the removal of
a key-bearing recording: transcripts are wire-only and `verify` has no `--record`. The `0x73` TLV,
the verdict word at `+8`, the 20-byte value at `+32` and both lengths are scripted-test only.
`docs/protocol-notes.md` records what a hardware run must capture; nothing is claimed as measured.

Hardware: `sudo ./target/debug/cvctl verify` with the enrolled finger (match) and with an unenrolled
one (no match, exit 9). Record the no-match reply detail in `docs/protocol-notes.md`.

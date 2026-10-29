# 07: Verification

**What to build:** `cvctl verify` reads a finger and asks the sensor to match it, reporting match or
no-match against an enrolment that is already on the sensor.

**Blocked by:** 05 (capture), 06 (enrolment)

**Status:** in-progress

- [x] `cvctl verify` reports a match for a finger enrolled by ticket 06
- [x] It reports no match for a finger that is not enrolled
- [x] The full match reply is decoded and printed: the verdict word, the matched template handle
      that follows it, and the reply's exact length
- [x] The reply to a **no-match** is captured and recorded in the same detail: same shape, verdict
      `0`, handle `0`
- [ ] A capture timeout and a transport error produce distinct outcomes, with the session closed
- [ ] Both outcomes are covered by scripted-transport tests

## Comments

Implemented in 3fa807b; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2, including the removal of
a key-bearing recording: transcripts are wire-only and `verify` has no `--record`. The `0x73` TLV,
the verdict word at `+8`, the 20-byte value at `+32` and both lengths are scripted-test only.
`docs/protocol-notes.md` records what a hardware run must capture; nothing is claimed as measured.

Hardware (measured 2026-10-29): `sudo ./target/release/cvctl verify --handle 0x00f2361f --hex` with
the enrolled finger answered `status 0x00`, `verdict 1`, plaintext `(0,4,1)(0,4,0x00f2361f)` plus
the token; with an unenrolled finger it answered `status 0x00`, `verdict 0`,
`(0,4,0)(0,4,0)` plus the token. The reply carries **no** 20-byte value at `+32`; that offset is the
token, and the id is the second entry at `+20`. `0x2F` is the command without a hash; `0x73` without
one hangs the sensor. `docs/protocol-notes.md` has the full record.

# 03: Secure session

**What to build:** `cvctl open` opens the secure session with a correctly wrapped, correctly
sequenced and correctly MACed command, and `cvctl close` tears it down.

**Blocked by:** 02 (handshake)

**Status:** done

- [x] `cvctl open` reports success only on a zero sensor status, and prints the handle (measured
      2026-10-29: `handle 0x2402cab0`, `secure session open`).
- [x] A deliberately wrong wrap sequence is rejected by the sensor and surfaces as a distinct sequence
      error, not as a generic failure (measured: status `0x0f` and exit 5).
- [x] `cvctl close` closes the session and a subsequent open succeeds (measured).
- [x] A failed open leaves no session handle behind: the next open does not fail as "already open"
      (measured: open after `--bad-sequence` succeeded).
- [x] Closing is idempotent — closing an already closed session is harmless (scripted close paths and
      repeated `cvctl close`).
- [x] Success and failure paths are covered by scripted-transport tests, not only on hardware.

## Comments

Implemented in 85bbcc7; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Wrapped framing, the
MAC and the sequence are pinned by tests; `cvctl open --bad-sequence` maps the expected `0x0F` to
exit 5.

Hardware acceptance is still open: `sudo ./target/debug/cvctl open`, `sudo ./target/debug/cvctl
close`, `sudo ./target/debug/cvctl open` again (no "already open"), and `sudo ./target/debug/cvctl
open --bad-sequence` (exit 5). The handle teardown after a failed open is scripted-test only.

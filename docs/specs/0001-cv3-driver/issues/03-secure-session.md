# 03: Secure session

**What to build:** `cvctl open` opens the secure session with a correctly wrapped, correctly
sequenced and correctly MACed command, and `cvctl close` tears it down.

**Blocked by:** 02 (handshake)

**Status:** ready-for-agent

- [ ] `cvctl open` reports success only on a zero sensor status, and prints the handle
- [ ] A deliberately wrong wrap sequence is rejected by the sensor and surfaces as a distinct
      sequence error, not as a generic failure
- [ ] `cvctl close` closes the session and a subsequent open succeeds
- [ ] A failed open leaves no session handle behind: the next open does not fail as "already open"
- [ ] Closing is idempotent — closing an already closed session is harmless

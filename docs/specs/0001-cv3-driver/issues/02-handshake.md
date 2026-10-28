# 02: Handshake

**What to build:** `cvctl handshake` runs the sensor's `0x23`/`0x24` exchange and derives the
session key from the ECDH secret and both nonces, proving the cryptography end to end and giving the
first hardware fact.

**Blocked by:** 01 (transport and enumeration)

**Status:** ready-for-agent

- [ ] `cvctl handshake` completes against the sensor and prints the session handle, the length of
      each nonce, and a fingerprint of the derived key — the raw key only behind an explicit flag
- [ ] Each run generates a fresh host keypair, so the host public key differs between runs
- [ ] A rejected challenge, a short reply and a status error are each reported as distinct failures
      without panicking
- [ ] A full-handshake test vector derives the expected key from a recorded exchange, so a refactor
      in the key schedule fails loudly
- [ ] The exchange is driven through the engine's event/action seam, with no I/O in the core

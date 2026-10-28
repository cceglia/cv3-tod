# 02: Handshake

**What to build:** `cvctl handshake` runs the sensor's `0x23`/`0x24` exchange and derives the session
key from the ECDH secret, the device nonce and the host nonce, proving the cryptography end to end.

**Blocked by:** 01 (transport and enumeration)

**Status:** ready-for-agent

- [ ] `cvctl handshake` completes against the sensor and prints the session handle, the length of
      each nonce, and a fingerprint of the derived key — the raw key only behind an explicit flag
- [ ] Each run generates a fresh host keypair, so the host public key differs between runs
- [ ] A rejected challenge, a short reply and a status error are each reported as distinct failures
      without panicking
- [ ] The key schedule uses the device nonce and the nonce sent in the challenge response, never the
      client nonce from the first challenge
- [ ] A full-handshake test vector, constructed from the protocol description rather than captured,
      derives the expected key; per-primitive known-answer tests cover AES-CBC, HMAC, SHA-1 and ECDH
- [ ] The exchange is driven through the core's event/action seam, with no I/O in the core

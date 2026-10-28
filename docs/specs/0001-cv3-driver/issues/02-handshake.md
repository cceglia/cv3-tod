# 02: Handshake

**What to build:** `cvctl handshake` runs the sensor's `0x23`/`0x24` exchange and derives the session
key from the ECDH secret, the device nonce and the host nonce, proving the cryptography end to end.

**Blocked by:** 01 (transport and enumeration)

**Status:** ready-for-human

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

## Comments

Implemented in 4386373; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Offline validation
passes, including the full handshake vector (key `6352f380005c4ebf33ce5ae1aad71e6f`) and the
per-primitive KATs.

Hardware acceptance is still open: `sudo ./target/debug/cvctl handshake` twice (a fresh host public
key each run, never "already open"), and `--show-key` only when the raw key is wanted. The `0x23`
reply is accepted at 192 bytes or longer because the write-up says the device nonce may be 24 bytes;
the short-reply failure is separate.

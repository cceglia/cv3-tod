# Protocol notes

Facts and readings about the ControlVault 3 command protocol. Every entry says where it comes from:
**measured on this sensor** (with a date and the run that produced it), or **read from the
reference material** (the audited third-party implementation and its write-up, kept outside the
build). Most of this document is the second kind today; it exists so the difference is never
blurred.

## Measured on 2026-10-28

Measured with `cvctl` on the sensor, in a root hardware run whose log is
`target/hardware-acceptance-20261028-200518.log`:

- **Handshake.** A fresh host keypair completes the `0x23` / `0x24` exchange. Two consecutive
  handshakes produced different host public keys and different session key fingerprints.
- **Wrapped open.** The wrapped `0x02` open succeeds at sequence 0, on a fresh session and again
  after a close.
- **Sequence rejection.** A deliberate sequence 1 on a fresh session is rejected with `0x0F`
  (`cvctl open --bad-sequence`).
- **Reply encoding.** The `0x66` capture reply carries encoding `0x03` in the frame header, while
  the wrapped command the host sends carries `0x02`. The driver accepted only `0x02` before this
  run and refused every reply; it now accepts both (see `Encoding::WrappedReply`).
- **Device nonce.** The device nonce is 20 bytes as this driver reads it at `HEADER_LEN + 128`.

Steps 05–09 of that run all failed at the reply-encoding check above, so the run measured nothing
beyond these points: no capture, match reply or binding fact comes from it.

## Wrap sequence

The wrap sequence is the per-session counter the driver and the sensor keep in step while a
secure session is open. The wrapped `0x02` open consumes zero. Each later wrapped command is MAC'd
over its sequence and the sensor rejects a mismatch with `0x0F`. Plain frames (`0x23`, `0x24`,
`0x04`, `0x8A`, `0x68`) never touch it.

### The two readings

- **Reference reading.** The audited reference's `bump_seq` advances after a wrapped command's
  reply whenever the reply carried a body and its status was not `0x0F`. A `0x85` "capture
  pending" reply therefore advances the counter, and the re-arm after a mid-session cancel carries
  N+1.
- **Capture-pending-keeps-sequence reading.** `0x85` is a refusal: the sensor did not consume the
  command, so the counter stays at N and the re-arm carries N.

The readings differ only on a body-bearing `0x85`. A body-less reply and `0x0F` never advance under
either reading.

### Which one the driver uses

Exactly one predicate decides: `advances_sequence` in `crates/cv3-core/src/session.rs`, applied at
the single point `Session::note_wrapped_reply`. The shipped reading is `SequenceRule::SHIPPED`,
currently `SequenceRule::Reference`. Switching the shipped reading is a one-line change to that
constant. Both readings are covered by the scripted-transport scenarios in
`crates/cv3-core/tests/cancellation.rs`.

### Measurement status

**Not measured.** This project has not observed the sensor's counter after a `0x85` reply, nor any
of the sequence behaviour in this area on hardware. The reference reading is what the audited
implementation does; the alternative is another reading of the same exchange. Neither has been
confirmed against this sensor. Treat the shipped rule as the more likely reading, not as a fact.

### How `cvctl cancel-then-verify` settles it

The command owns **one** session and sends:

```
0x02 open → 0x66 arm (reply consumed, no finger) → mid-session 0x68 →
0x66 arm → finger → 0x73 match → 0x68 (teardown) → 0x04
```

If the first arm answers `0x85` — a capture was already armed — the run consumes that reply,
cancels the stale capture with the session-scoped `0x68`, and re-arms. The second arm's wrap
sequence is then the number in dispute: N+1 under the reference reading, N under the alternative.
The sensor accepting the second arm says the shipped reading matches; a `0x0F` there says it does
not, and the fix is to change `SequenceRule::SHIPPED` to the other variant and run again.

If the first arm answers zero, the run has **not** exercised the `0x85` case. It has only shown
that the sequence survives a plain mid-session cancel. The pending case arises when a capture was
left armed by an earlier run that could not clean up (for example an uncatchable `kill -9`
mid-capture); it is the case to look for when reading a hardware run.

The observation is the sensor's answer to the second arm, not the printed verdict: the sequence
lives inside the MAC and is not printed.

## Match replies

**Not measured.** Ticket 07 requires that the reply to a no-match be captured in the same detail as
a match. A hardware run must record, for a match and for a no-match:

- the verdict word at plaintext `+8`, exactly as the sensor sent it;
- whether a 20-byte value is present at plaintext `+32` (that is, whether the decrypted plaintext
  is at least 52 bytes) and, if present, whether it equals the value the enrolled print returned;
- the exact wrapped reply body length and the exact decrypted plaintext length.

The question is load-bearing: if a no-match reply already carries the enrolled finger's value at
`+32`, then flipping the verdict word would pass an id comparison, and ticket 10's binding would
not be a defence. Until the run is written down here, the driver assumes nothing about the value.
Do not fill these fields in from the reference or by inference.

## Binding

Not yet established. Ticket 09 owns the binding facts: whether the sensor accepts a capture and a
match immediately after a commit, what the 20-byte value at the match reply's `+32` is, and whether
it is stable across sessions. Nothing in this document should be read as a finding until that
ticket records it here.

## Inventory

Not yet established. Ticket 16 owns the `0x2F` inventory query and the reply format. The reference
only dumps the reply; that is not a decoded format.

## Deletion

Not yet established. Ticket 21 owns whether a delete command exists at all. Until then, deletion is
reported as unsupported rather than emulated.

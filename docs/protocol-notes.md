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

The acceptance run whose log is `target/hardware-acceptance-20261028-201206.log` then measured:

- **Capture, enrolment, timeout and signal.** `0x66` capture, the whole
  `0x6D`/`0x8A`/`0x6C`/`0x6E` enrolment, the finger timeout, and SIGINT during the finger wait
  all completed. The enrolment committed and reported a sensor **enrolment id**
  (`80f5eb3d7e7e2034cd960db24c059208b41586c3` in step 06, `b05432744322b732b58b5d54e2812ed7603ffab2`
  in step 09).
- **`0x73` refused with `0x59`.** For both an enrolled and an unenrolled finger, the match request
  as the audited reference builds it — a 68-byte TLV whose final `(3, 20)` entry carries no value
  bytes — was answered `0x59`. The request now completes that entry with the 20-byte template id
  (88-byte TLV, 128-byte plaintext). **The completed request has not been measured.**
- **Re-arm after a cancel.** In `cancel-then-verify` the first arm answered `0x00` at sequence N,
  the mid-session cancel left the session open, and the re-arm at N+1 was rejected with `0x0F`.
  The first arm did not answer `0x85`, so this run did not exercise the capture-pending case.

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

The re-arm after a plain mid-session cancel is **not** this predicate: it is the measured rewind in
`Session::rewind_sequence`, applied by `cvctl cancel-then-verify` (see below).

### Measurement status

**Measured for the plain arm, not for `0x85`.** On 2026-10-28
(`target/hardware-acceptance-20261028-201206.log`) the first arm answered `0x00`, the mid-session
`0x68` cancelled it, and the re-arm at N+1 was rejected with `0x0F`: the sensor still expected the
arm at N. That run did not produce a `0x85`, so the case the two readings actually disagree about —
whether a capture-pending reply advances the counter — is still unmeasured. Do not read the `0x0F`
above as settling the `0x85` question.

The driver's default is therefore the **same-sequence retry**: it rewinds the counter by one after
the cancel. `Session::rewind_sequence` is that rewind, and its doc points back here.
`SequenceRule::SHIPPED` remains the reference reading for the `0x85` predicate; the rewind is a
separate, measured step, not a change to that predicate.

### How `cvctl cancel-then-verify` tests it

The command owns **one** session and sends:

```
0x02 open → 0x66 arm (reply consumed, no finger) → mid-session 0x68 →
0x66 arm → finger → 0x73 match → 0x68 (teardown) → 0x04
```

It prints the first arm's status (`0x00`, `0x85`, …) and the sequence each `0x66` carries.

- **Default:** the second arm carries the first arm's sequence (N), the measured behaviour.
- **`--retry-next`:** the second arm carries N+1, the older/reference reading, kept so the
  measurement can still be repeated.

If the first arm answers `0x85` — a capture was already armed — the run consumes that reply,
cancels the stale capture with the session-scoped `0x68`, and re-arms. That is the case that tests
the `0x85` predicate itself. If the first arm answers zero, the run has only shown how a plain
mid-session cancel affects the sequence.

The observation is the sensor's answer to the second arm, not the printed verdict: the sequence
lives inside the MAC. The printed `re-arm sequence` line says which number was sent.

## Match replies

**`0x59`, but no verdict yet.** On 2026-10-28 (`target/hardware-acceptance-20261028-201206.log`)
the `0x73` request as the reference builds it was refused with `0x59` for both an enrolled and an
unenrolled finger. The driver now completes the final `(3, 20)` entry with a template id; that
88-byte request is **not yet measured**, so the verdict word, the value at `+32` and the no-match
reply remain unobserved.

A hardware run must record, for a match and for a no-match:

- the verdict word at plaintext `+8`, exactly as the sensor sent it;
- whether a 20-byte value is present at plaintext `+32` (that is, whether the decrypted plaintext
  is at least 52 bytes) and, if present, whether it equals the value the enrolled print returned;
- the exact wrapped reply body length and the exact decrypted plaintext length.

A non-zero `0x73` status must also record its raw reply length and, when the body decrypts, the
decrypted plaintext length and hex. `cvctl` prints those diagnostics; a `0x59` that still carried a
body is then visible instead of being reduced to the status alone.

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

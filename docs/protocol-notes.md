# Protocol notes

Facts and readings about the ControlVault 3 command protocol. Every entry says where it comes from:
**measured on this sensor** (with a date and the run that produced it), or **read from the
reference material** (the audited third-party implementation and its write-up, kept outside the
build). Most of this document is the second kind today; it exists so the difference is never
blurred.

## Host timestamp request (interrupt type 5)

**Read from the reference, not yet measured with this probe.** Interrupt endpoint `0x85` can
deliver a first `u32` of `5`, which Dell's Windows driver calls
`CV_GET_HOST_TIMESTAMP_INTERRUPT`. The Windows driver demultiplexes it before completing a pending
command; Broadcom's Linux driver does not, attempts the next bulk read and times out, which aborts
enrolment.

The host answers with a vendor/device OUT control request:

- `bmRequestType = 0x40` (vendor, device, host to device)
- `bRequest = 0x0d`
- no data stage
- `wValue` is the low 16 bits of the packed timestamp, `wIndex` the high 16 bits

The packed `u32`, least significant bit first:

| Field | Bits |
|---|---|
| day | 0..4 |
| month | 5..8 |
| year since 2000 | 9..14 |
| hour | 15..19 |
| minute | 20..25 |
| second | 26..31 |

The vendor packs **local** civil time; this probe packs **UTC**, because a `SystemTime` carries no
timezone. The field widths and positions are what the controller consumes, so the encoding is
otherwise identical. The year field is six bits (2000..2063) and saturates at either end.

`cvctl` answers type-5 events in the USB transport — during both the reply-announcement read and
the finger wait, with a bounded number of retries. It does **not** send the sync unprompted: on
2026-10-29 an unsolicited sync at session start timed out and the handshake that followed also
timed out, so the probe now waits for the sensor to ask. With `--hex` the host-side control appears
as `* timestamp <packed:08x>`, alongside the `>`/`<` bulk lines.

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
- **`0x73` refused with `0x59`, with the old CV2-shaped request.** For both an enrolled and an
  unenrolled finger, the request as the audited reference builds it — the ControlVault 2
  parameter block, whose last `(3, 20)` entry carried no value bytes — was answered `0x59`.
  Completing that entry with the 20-byte template id (an 88-byte TLV, 128-byte plaintext) changed
  the answer to `0x0E`. That request still carried the CV2 constants; the corrected ControlVault 3
  request below is different and **has not been measured**. The same `0x0E` came back from the
  `0x2F` query with the reference's 56-byte TLV (a body-less 44-byte reply).
- **`0x72` is verify; `0x73` is identify.** Disassembly of the vendor blob
  (`extracted/broadcom/.../libfprint-2-tod-1-broadcom.so`) shows `cv_do_fingerprint_verify` calling
  `cvhManageCVAPICall` with command `0x72` and `cv_do_fingerprint_identify` calling it with `0x73`.
  The TOD's Linux match path is `cvif_fingerprint_identify` → `cv_fingerprint_identify(handle,
  0x48, 0x53e2, 0, count, ids, …)`, so `0x73` is the vendor's **one-to-many identify with `u32`
  template handles**; `0x72` is the one-to-one verify. Both statuses `0x00` and `0x89` are treated
  as "answered" because the vendor special-cases `0x89`; the verdict is still read from the reply
  body. The probe defaults to `0x73` and keeps `--command 72` for the one-to-one variant.
- **Commit id.** Committing with the sensor's enrolment id succeeded (`0x00`); committing with the
  last sample hash instead was refused with `0x8E`. The enrolment id is the id to commit.
- **Re-arm after a cancel.** In `cancel-then-verify` the first arm answered `0x00` at sequence N,
  the mid-session cancel left the session open, and the re-arm at N+1 was rejected with `0x0F`.
  Re-arming at N was also rejected with `0x0F`, so the plain cancel does not simply leave the
  counter unchanged. The first arm did not answer `0x85`, so this run did not exercise the
  capture-pending case.

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

## Match request (identify)

**Read from the vendor blob, not yet measured.** `cv_do_fingerprint_identify` builds its request
parameter list as:

```text
(0, 4, handle)
(0, 4, 0x48)
(0, 4, 0x53e2)
(0, 4, 0)
(2, 4 * count, count × u32 template handles)
(3, 20, hash)                 only when a hash pointer is supplied
```

Each wire entry is `u32 type | u32 size | value bytes`, with no padding beyond the value bytes.
`InitParam_List` and `cvhDecapsulateCmd` confirm that shape. The public Linux path
`cvif_fingerprint_identify` (0x2b2e0) calls `cv_fingerprint_identify(handle, 0x48, 0x53e2, 0,
count, ids, …)`, so the array values are `u32` template handles, not 20-byte ids.

The command depends on the hash argument, not on the caller's intent: at `0x24348`
`cv_do_fingerprint_identify` tests the hash pointer, and

- **with** a hash pointer it sends **`0x73`** (the request then also carries `(3, 20, hash)`);
- **without** one it sends **`0x2F`** (`push 0x2f` at `0x24590`), with the same parameter list and
  attr `0x47`.

Sending `0x73` without the hash is what this driver did on 2026-10-29: the sensor ACKed the bulk
OUT and then never announced a reply (60 s), so the request is only valid for the hash form. A
`0x2F` with attr `0x42` is a different request — the inventory query ticket 16 owns.

The lengths are therefore `56 + 4 * count + (28 when a hash follows)`:

| Handles | Hash | TLV | Plaintext |
|---|---|---|---|
| 0 | no | 56 | 96 |
| 1 | no | 60 | 96 |
| 0 | yes | 84 | 128 |
| 1 | yes | 88 | 128 |

The plaintext is the TLV plus the 32-byte token, rounded up to a whole AES block; PKCS#7 then adds
one more block. The type-2 entry is always present, with size zero when no handle is named; what a
zero-size entry asks the sensor to do is not established and the next hardware run measures it.

**The CV2 values in this driver were wrong for CV3.** `0x148` and `0x7b0ad3` do not occur in the
blob as constants at all; they came from the audited reference, which targets ControlVault 2, and
`0x53e2` occurs exactly once, as the argument above. `crates/cv3-core/src/verify.rs` now builds
only the vendor list. **The corrected request has not been measured on this sensor yet.**

## Match replies

**Measured 2026-10-29.** A fresh enrolment committed template handle `0x00f2361f` (the `0x6E`
reply's second entry, `(0,4,0x00f2361f)`, next to `(3,0)`), and `verify --handle 0x00f2361f`
answered:

```text
status 0x00
plaintext (56 bytes): (0,4,1) (0,4,0x00f2361f) then 32 token bytes
```

So the verdict word is at plaintext `+8` (1 = match), the matched template handle at `+20`, and
there is no 20-byte value at `+32` — that offset lands inside the token.

Other statuses measured the same day:

- A handle from a commit made before several power cycles was refused with **`0x59`** (invalid
  parameter), so a template handle does not survive a power cycle in the request.
- The hash form (`0x73 --template <enrolment id>`) answered **`0x0E`** with a 32-byte body; it is
  not a match, and its exact meaning is unestablished.
- `0x73` without a hash is not accepted: the bulk OUT was acknowledged, no announcement ever came,
  and the sensor needed a power cycle.

The **no-match** reply was measured the same day, with the same handle and an unenrolled finger:

```text
status 0x00
plaintext (56 bytes): (0,4,0) (0,4,0) then 32 token bytes
```

So a no-match is status `0x00`, verdict word `0`, matched handle `0`, with the same shape and
lengths as a match. `cvctl` prints the verdict word, the matched handle, both lengths and the TLV
scan for any answered status. Still unmeasured: whether the handle survives a power cycle.

## Binding

Measured 2026-10-29:

- **The matched id is the template handle.** The match reply's second entry is the `0x6E` reply's
  `(0,4,…)` value, not a biometric-derived hash.
- **The handle survives a power cycle.** Template `0x00f2361f` was enrolled, the machine was
  rebooted, and `verify --handle 0x00f2361f` still answered `status 0x00`, `verdict 1`,
  `(0,4,1)(0,4,0x00f2361f)`.
- **A no-match carries the same shape with zeros**: `(0,4,0)(0,4,0)`.
- **There is no 20-byte value at `+32`**: the reference's value was the token.

Also measured: **a capture and a match immediately after a commit, in the same session**, work.
`enroll-then-verify` committed handle `0x007069a9` and the confirmation touch answered `status 0x00`,
`verdict 1`, `matched handle 0x007069a9`.

A second finger was enrolled as `0x002f1a08`. Against it, `verify --handle 0x007069a9` answered
`verdict 0, matched handle 0`, and the first template still matched `0x007069a9` afterwards: a
print's handle is not satisfied by another finger's template, and a second enrolment does not move
the first handle.

The driver now stores that binding in the versioned print payload (`crates/cv3-core/src/print.rs`):
magic `CV3P`, version 1, flags, the enrolment id, and the match id. A verification is accepted only
when the print is bound, the reply has the measured shape, the verdict is `1` and the id equals the
recorded one. Unknown versions, foreign payloads and unbound records are typed errors.

## Inventory

Not yet established. Ticket 16 owns the `0x2F` inventory query and the reply format. The reference
only dumps the reply; that is not a decoded format.

## Deletion

Not yet established. Ticket 21 owns whether a delete command exists at all. Until then, deletion is
reported as unsupported rather than emulated.

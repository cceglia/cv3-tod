# A Rust driver for the ControlVault 3 fingerprint sensor

Status: ready-for-agent

## Problem Statement

The Dell Latitude's fingerprint sensor (Broadcom ControlVault 3, `0a5c:5843`) has no working
open-source Linux driver. The only implementation that drives it is a proprietary blob distributed
by Canonical, which does not work on this machine; `fprintd` therefore reports no device, and
fingerprint login, unlock and `sudo` are unavailable.

The one open-source implementation that does work is a 588-line C plugin from a single author with
a single day of history. It was audited and found free of malice, but it carries a root-reachable
stack overflow, trusts an unauthenticated verdict from the sensor, and has no way to delete a
template from the sensor's store. Its author stopped at the point where the sensor's template
inventory would have to be decoded, so verification can only answer "some enrolled finger", never
"this user's finger".

I do not want to run unaudited third-party C as root, and I do not want a fingerprint reader whose
verdict can be forged by flipping one bit of a reply.

## Solution

Write the driver ourselves, in Rust, with the protocol work kept away from C entirely.

A Rust core speaks the sensor's protocol — the ECDH handshake, the secure session, the wrapped
command channel, enrolment, matching, and the template inventory — and performs no I/O. A thin C
shim, written by us and containing no protocol logic, presents the core to `libfprint` through its
TOD interface so that `fprintd`, `pam_fprintd`, GNOME/KDE settings and every PAM-based lock screen
work unchanged. A small probe binary, driven from the same core, runs against the sensor directly
so protocol facts can be established on hardware without installing anything.

The result behaves like a normal `fprintd` reader: enrol, verify, list and delete, with the sensor's
own store as the source of truth. Verification is bound to the print that was enrolled, not merely
to the presence of any enrolled finger, so a forged or replayed reply cannot authenticate someone
who was never enrolled.

## User Stories

1. As a laptop owner, I want `fprintd-list` to show my fingerprint reader, so that I know the driver
   is installed and the sensor is recognised.
2. As a laptop owner, I want to enrol a finger through GNOME Settings, so that I never have to use a
   command line to set up biometric login.
3. As a laptop owner, I want to enrol a finger with `fprintd-enroll`, so that the same flow works on
   a headless machine.
4. As a laptop owner, I want each of the twelve enrolment touches to report progress, so that I know
   the sensor is accepting samples and how many remain.
5. As a laptop owner, I want a sample the sensor rejects to be re-requested rather than aborting the
   enrolment, so that a poorly placed finger does not cost me the whole attempt.
6. As a laptop owner, I want enrolment to stop when the sensor says it has enough samples, so that
   extra touches do not corrupt the stored template.
7. As a laptop owner, I want enrolment to fail cleanly with a clear message if I never complete the
   required samples, so that I am not left wondering whether it worked.
8. As a laptop owner, I want `fprintd-verify` to report a match when my enrolled finger is read, so
   that I can test the reader without locking my screen.
9. As a laptop owner, I want `fprintd-verify` to report no match for an unenrolled finger, so that I
   can trust the result.
10. As a laptop owner, I want verification to be tied to the specific finger I requested, so that
    verifying the right index finger does not succeed because a different enrolled finger was
    presented.
11. As a laptop owner, I want an unenrolled finger presented during verification to fail even when
    another user on the machine has enrolled their own finger, so that sharing a laptop does not
    mean sharing accounts.
12. As a laptop owner, I want a forged or interposed reply to be rejected, so that the fingerprint
    is not a decorative check.
13. As a laptop owner, I want cancelling a verification to stop immediately and leave the sensor
    usable, so that an abandoned prompt does not wedge the reader or block the next attempt.
14. As a laptop owner, I want to cancel a verification by pressing Escape in the `sudo` prompt, so
    that I can fall back to my password without waiting.
15. As a laptop owner, I want the password to remain available whenever the fingerprint fails, so
    that a broken sensor can never lock me out.
16. As a laptop owner, I want `sudo` to accept my fingerprint through `pam_fprintd`, so that I do not
    have to type a password for administrative commands.
17. As a laptop owner, I want my lock screen to unlock on a fingerprint, so that resuming the
    machine does not require typing.
18. As a laptop owner, I want `fprintd-list` to show the fingerprints stored on the sensor, so that I
    can see what is enrolled rather than guessing.
19. As a laptop owner, I want `fprintd-delete` to remove a fingerprint from the sensor, so that a
    revoked finger genuinely stops working.
20. As a laptop owner, I want deletion to be reported as unsupported rather than faked if the sensor
    has no delete command, so that I am not told a finger is gone when it still matches.
21. As a laptop owner, I want a "clear all fingerprints" operation, so that I can reset the reader
    before selling or lending the machine.
22. As a laptop owner, I want identification (one-to-many) to work where the sensor supports it, so
    that the login screen can match without telling the driver which finger to expect.
23. As a laptop owner, I want the driver to report a clear error when the sensor is absent or held by
    another process, so that I can tell "no reader" from "reader busy".
24. As a laptop owner, I want the driver to recover a sensor left in a stuck state by an interrupted
    session, so that a killed process does not require a reboot.
25. As a laptop owner, I want the driver never to reset the USB port, because that is what turns a
    recoverable wedge into a sensor that needs a power cycle.
26. As a laptop owner, I want the driver to leave no session handle open when it fails, so that the
    next attempt does not fail with "already open".
27. As a laptop owner, I want to uninstall the driver by deleting one file, so that trying it is not
    a commitment.
28. As a second user on a shared laptop, I want my fingerprint to authenticate only my account, so
    that my colleague cannot log in as me.
29. As a security reviewer, I want the code that parses bytes from the device to contain no unsafe
    code, so that a malformed or hostile reply produces an error rather than memory corruption.
30. As a security reviewer, I want the protocol constants and frame layout documented in one place
    with tests pinning the wire offsets, so that I can check the implementation against the wire
    format without reading a decompiler's output.
31. As a security reviewer, I want the driver to state honestly what a match proves, so that nobody
    mistakes it for a user-bound credential when it is not.
32. As the developer reverse-engineering the protocol, I want a probe that sends one command at a
    time and dumps both directions as hex, so that I can establish facts the documentation gets
    wrong.
33. As the developer, I want to replay a recorded session offline, so that a behaviour seen once on
    hardware becomes a test that runs everywhere.
34. As the developer, I want the probe to refuse to run while `fprintd` holds the sensor, so that I
    do not wedge the chip by fighting over the interface.
35. As the developer, I want the probe to print the sensor's template inventory before and after an
    enrolment, so that I can learn the id the sensor assigned without a decompiler.
36. As the developer, I want a single place where the wrap-sequence rule lives, so that the two
    contradictory readings of the reference implementation can be settled by changing one predicate
    and re-running the probe.
37. As a maintainer, I want the protocol core to have no I/O dependencies at all, so that its test
    suite needs neither hardware nor a runner with USB access.
38. As a maintainer, I want the C surface limited to the `libfprint` interface, so that an audit of
    the part running as root never has to reason about parsing.
39. As a maintainer, I want the same core to drive both the probe and the plugin, so that a fact
    established in the probe is reproduced in the shipping path rather than rediscovered.
40. As a distro packager, I want the plugin to be a single shared object built against the distro's
    `libfprint` TOD headers, so that packaging needs no patched `libfprint`.
41. As a distro packager, I want the build to fail loudly when it links against the wrong symbol
    version, so that a broken plugin never reaches a user as a `fprintd` crash.
42. As a licence-conscious user, I want the project's provenance recorded, so that credit for the
    reverse-engineering and the limits of what was reused are both explicit.

## Implementation Decisions

**Shape.** A Rust workspace with three crates: the protocol core, the probe, and the TOD plugin. The
core has no I/O in its dependency list, which makes "the core performs no I/O" a compile-time fact
rather than a convention (ADR-0001). The plugin crate is a `cdylib` containing the C shim, built
only when the `libfprint` TOD headers are present.

**Core interface.** One engine object owns all session state and exposes a single step function:
it takes an event and returns the action to perform next. Events are: a reply arrived with a status
and body, a reply arrived with no body, a finger event arrived, the transport failed, and the
operation was cancelled. Actions are: transmit bytes on an endpoint with a timeout class, wait for a
finger event, and finish with a result. There is no callback, no thread and no timer inside the core:
the transport owns time.

**Transport contract.** A transport sends bytes and returns one of: a reply (status and body), an
empty reply, a transport error, or cancellation. The transport performs the out/interrupt/in
exchange the protocol requires and hides it from the core; the core never learns about endpoints.
Two real implementations exist — the probe's, over a pure-Rust USB stack, and the shim's, over
`libfprint`'s asynchronous transfers — plus a replay implementation used by tests and by the probe's
replay mode.

**Cryptography.** Pure-Rust primitives with no OpenSSL: AES-128-CBC with PKCS#7, HMAC-SHA-256,
SHA-1, and P-256 ECDH. The host keypair is generated per session; the sensor does not authenticate
the host, so no key material is stored. The key schedule follows the observed protocol: the shared
secret, hashed, then combined with both nonces to produce the session key. The per-command MAC
covers the header, the parameter block and the wrap sequence. The session key is zeroed when the
session closes. Every primitive is pinned by known-answer vectors in addition to the protocol-level
tests.

**The wrap-sequence rule lives in exactly one predicate.** The two reference implementations
disagree about whether a "capture pending" reply advances the sequence. A single function decides,
and the first probe session answers it; the tests cover both readings so the decision is a one-line
change rather than a rewrite.

**Enrolment.** Discard any pending enrolment, start, then loop: arm a capture, wait for the finger
event, submit the sample. Accepted samples advance progress; unusable samples are re-requested; the
sensor's "no more samples" reply stops the loop. Completion is recognised when the reply carries a
**match id** distinct from the **sample hash** that was submitted; committing is refused when fewer
than the required stages were accepted. The commit uses the last known template identifier.

**Verification.** Arm a capture, wait for the finger event, request a match. Success requires the
sensor to report a match *and* the returned **match id** to equal the one recorded for the print
being verified. When the printed data predates id binding, or the sensor's match id proves unstable
across sessions, the driver degrades to trusting the match flag and says so through a warning rather
than silently. That degradation is a runtime decision, not a build feature (ADR-0002).

**Print payload.** The data stored per print is a fixed, versioned binary record: a magic and
version, the **enrolment id**, the **match id**, and flags recording which of them are meaningful.
No serialisation dependency, no JSON, no schema. Unknown versions are rejected rather than guessed.

**Storage model.** The sensor's store is the source of truth. Where the inventory query can be
decoded, the driver maps templates to prints with a **store diff** taken around each enrolment, and
declares the storage, list and delete features to `libfprint`. Where it cannot, the driver stores
prints host-side with the recorded match id and declares neither list nor delete. Both paths remain
implemented and tested; which one is active is observable through the features the driver reports.

**Deletion.** Deletion is a sensor operation when an opcode for it is known. If none is found, the
driver reports deletion as unsupported and keeps the print visible; it never emulates deletion by
overwriting, because a finger that "was deleted" but still matches is worse than one that cannot be
deleted.

**The shim.** C, and deliberately trivial: a GObject subclass of the `libfprint` device type whose
virtual functions forward to the core, and a transfer binding that performs what the core asks. It
contains no parsing, no arithmetic on lengths, no crypto and no state beyond what the interface
requires. It exports the single entry point `libfprint` looks for. It must link the versioned TOD
symbols; the build is required to fail rather than silently bind the legacy compatibility thunk.

**Timeouts.** Commands use a generous fixed timeout, replies a longer one, and the finger wait a
shorter one, all as constants with one explaining comment. Command transfers are never cancellable;
only the finger wait is. This is a safety property of the hardware, not a preference.

**Failure and recovery.** On any failure the driver cancels a pending capture and closes the session
handle before reporting the error, because a dangling handle survives reboots. It never resets the
USB device and never touches the port's `disable` knob. Recovery from a sensor wedged by an external
kill is an operator action, documented, using the USB `authorized` toggle.

**Probe.** `cvctl` runs one operation at a time and prints both directions as hex with decoded
fields. Subcommands cover the handshake, opening and closing a session, verification, enrolment, the
inventory query, and replaying a recording. It refuses to run while `fprintd` is active, requires
root, and never resets the device.

**Errors.** Protocol failures map onto `libfprint`'s device errors so that `fprintd` reports
"retry", "no match" or "device error" rather than a generic failure.

**Dependencies.** A small, pinned set of pure-Rust crypto crates, audited in CI for advisories and
licences. No transport crate in the core, no OpenSSL, no build scripts where avoidable.

**Licence and provenance.** MIT, with a notice crediting the reverse-engineering that made the
protocol known and stating that no vendor code or firmware is redistributed.

## Testing Decisions

A good test here asserts **wire behaviour and observable outcomes**, never internal structure: given
this conversation, the driver must want to send these bytes, or must report this result. Tests do not
reach into engine fields, do not assert on private state machines, and do not mock the crypto.

**The engine seam is where nearly everything is tested.** A test scripts a sensor: replies to feed,
a finger event, a cancellation, a transport error. It asserts the sequence of actions requested and
the final outcome. Scenarios cover: handshake success and rejection, wrong sequence, capture pending,
capture cancelled, sample rejected and retried, enrolment completing early, enrolment running out of
samples, match, no match, id mismatch, unstable id, empty inventory, inventory diff, delete
unsupported, and transport failure at each state. Fixtures are synthetic, built from the same codec
that the tests pin independently, so a fixture cannot drift silently from the frame definition.

**The codec keeps its own tests**, because it is the one place where byte offsets matter: field
positions, both length fields, wrapped-versus-plain, and rejection of short, mis-magicked and
inconsistently-sized buffers. Random and structured buffers must never panic; a fuzz target
accompanies it. These five existing tests are the prior art for the style.

**The transport contract is tested once and run against every implementation.** The contract tests —
reply, empty reply, error, cancellation, timeout — run against the replay transport and against a
fake that injects failures. The probe's real transport and the shim's are not unit-tested; they are
exercised on hardware.

**Crypto is pinned twice**: known-answer vectors for each primitive, and one full handshake vector
whose session key and MAC are asserted, so a refactor in the key schedule fails loudly instead of
quietly producing frames the sensor rejects.

**Not tested automatically, by decision:** the C shim, the `fprintd` integration, and PAM. Their
acceptance is manual and scripted in the acceptance criteria; keeping the shim free of logic is what
makes that acceptable.

## Out of Scope

- Identification, listing and deletion until the inventory query is decoded; they are in the plan but
  gated on that work, and the driver must remain shippable without them.
- Suspend and resume handling.
- Firmware update, firmware version checks, and the chip's smartcard and RFID functions.
- Sensors other than `0a5c:5843`; other ControlVault models may be close but are untested and
  unclaimed.
- Reading fingerprint images: the sensor matches on-chip and never sends an image.
- Our own PAM module; `pam_fprintd` is the consumer.
- Upstreaming into `libfprint` as a native C driver.
- Windows, macOS, and anything that is not Linux.
- Enrolment quality tuning beyond reporting the sensor's own verdict.

## Further Notes

**Facts the first probe session must settle** (none of these can be decided from the documentation,
and at least one of them the documentation contradicts):

1. Whether a "capture pending" reply advances the wrap sequence.
2. Whether a **match id** is stable across sessions and reboots. If it is not, id binding degrades to
   trusting the match flag, and the spec's security claim narrows accordingly.
3. The inventory query's reply format, which is what unlocks list, delete and true revocation.
4. Whether a delete command exists at all.
5. Whether the sensor tolerates the chosen timeouts, given that an aborted command transfer is what
   wedges it.

**Risks.** A bug in the probe runs as root and can wedge the sensor's command interface; the
documented recovery is the USB `authorized` toggle, and the documented way to make it unrecoverable
is a port reset, which the driver never performs. A bad session may cost a power cycle.

**Acceptance for the first release** is: the probe proves handshake, verification, enrolment and the
inventory mapping on hardware; `fprintd-enroll`, `fprintd-verify`, `fprintd-list` and `fprintd-delete`
work; `sudo` authenticates through `pam_fprintd`; and a verification cancelled mid-capture is
followed by a successful one.

**Provenance.** The protocol was reverse-engineered by a third party under the MIT licence; their
write-up and implementation are the source of the constants, and an audit of that implementation —
including the defects this design must not inherit — is kept with the project's reference material.
The two load-bearing decisions are recorded as ADR-0001 (I/O-free core with a C shim) and ADR-0002
(device-stored prints with host-side fallback).

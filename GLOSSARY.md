# ControlVault 3 fingerprint driver

Driving the Broadcom BCM58200 ControlVault 3 fingerprint sensor from Linux: speaking its
encrypted command protocol and presenting the sensor to `fprintd` as a fingerprint reader.

## Language

### Hardware and transport

**Sensor**:
The Broadcom BCM58200 ControlVault 3 module on USB `0a5c:5843`, a match-on-chip fingerprint
reader that also carries smartcard and RFID functions.
_Avoid_: device, reader, reader chip

**Secure session**:
The per-connection encrypted channel that must be open before the sensor accepts any fingerprint
command. It has a handle and a key schedule derived during the handshake; it is not TLS.
_Avoid_: channel, tunnel

**Wrap sequence**:
The counter that the driver and the sensor keep in step while a session is open. A command carrying a
mismatched counter is rejected.
_Avoid_: nonce, sequence number, counter

**Host timestamp request**:
The interrupt event whose first word is `5`, answered with a vendor device control request carrying
the packed civil date and time. The vendor packs local time; the probe packs UTC.
_Avoid_: clock sync event, time command

**Light wedge** / **Deep wedge**:
A wedged sensor still enumerates on USB but refuses commands. A light wedge clears with a USB
`authorized` toggle; a deep wedge survives until the machine loses power.
_Avoid_: hang, lockup, bricked

### Protocol values

**Sample hash**:
The 20-byte value identifying one captured fingerprint image during enrolment.
_Avoid_: capture hash, image hash

**Enrolment id**:
The 20-byte identifier the sensor returns when an enrolment completes, naming the template it
just stored.
_Avoid_: print id

**Template id**:
The 20-byte value the `0x6E` commit submits to name the template the sensor stores. It is either the
sensor's **enrolment id**, when the sensor named one, or the fallback **sample hash** of the last
accepted sample; the enrolment records which of the two it used.
_Avoid_: template name, print id

**Match id**:
The 20-byte value the sensor returns alongside a positive match. The reference claims it is not the
enrolment id and that the two are not comparable; that claim is unestablished. What it is derived
from, and whether it is stable across sessions, is likewise unestablished.
_Avoid_: matched id

**Bound print**:
A print whose verification requires the sensor to report the same match id that was recorded for it.
The driver stores no other kind.
_Avoid_: bound template, linked print

**Device-stored print**:
A fingerprint whose template lives on the sensor, the host keeping only its identifier and
metadata. Deleting one is a sensor operation.
_Avoid_: chip print, stored print, on-chip print

**Host-stored print**:
A fingerprint whose record lives in fprintd's storage while the sensor holds the template. It can
still be bound, by recording the match id in the record; without one, verification would trust the
sensor's match flag alone.
_Avoid_: local print, fprintd print

**Store diff**:
The comparison of the sensor's template inventory before and after an enrolment, used to learn
which id the sensor assigned to the new template.
_Avoid_: store scan, inventory dump

### Our design

**Probe** (`cvctl`):
Our command-line tool that drives the sensor directly, one command at a time, to establish
protocol facts without installing a driver.
_Avoid_: test tool, debug tool

**Shim**:
Our thin C layer that turns libfprint's driver callbacks into events for the Rust core and
performs the actions the core returns. It holds no protocol logic.
_Avoid_: wrapper, glue, adapter

**Core**:
The Rust library that owns the protocol: framing, cryptography, session state and the enrol and
verify state machines. It performs no I/O.
_Avoid_: library, engine, backend

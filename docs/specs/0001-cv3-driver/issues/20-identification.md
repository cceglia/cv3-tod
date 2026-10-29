# 20: Identification

**What to build:** the login screen can match a finger without being told which account or finger to
expect, using the match ids every stored print already carries.

**Blocked by:** 14 (verify through fprintd), 10 (id binding)

**Status:** ready-for-human

- [x] Identification returns the print that actually matched, not merely that some print matched
      (scripted: the plugin test matches the second of two gallery prints and reports gallery index
      `1`; `Gallery::matched_index` accepts only the print whose recorded handle and measured reply
      shape the sensor returned, and only when that handle is unique in the gallery)
- [x] It succeeds for an enrolled finger and fails for an unenrolled one (measured 2026-10-29:
      right index matched the gallery print; left index answered `no match`).
- [ ] With two users enrolled, a finger identifies its own user's print and no other (hardware: the
      two-print gallery below, presenting each finger)
- [ ] The identify feature is declared only when prints are bound, and is independent of whether the
      sensor's inventory was decoded — not met literally in this ABI (see the caveat below): `FpDeviceClass.features` is static
      and libfprint 1.95 has no per-gallery bit, so `IDENTIFY` is declared with `VERIFY` and identify
      itself returns no match for an empty or unusable gallery. The request is `0x2F` attr `0x47`
      with the gallery's handles and never reads attr `0x42`.
- [x] A candidate list containing only unbound or foreign prints produces no match rather than a false
      one (scripted: empty, missing, foreign, unbound, wrong-version and duplicate-handle galleries
      all complete as a no-match with no capture and no command; a verdict `1` for a handle outside
      the candidates is also a no-match)

## Implementation notes

- **Core.** `cv3_core::identify` owns the whole behaviour. `Gallery::from_entries` decodes each
  print's `fpi-data` with `PrintPayload::decode`, drops records that are not this driver's bound
  version, drops handle `0` (the sensor's no-match sentinel), and drops every copy of a handle that
  two prints share. `Gallery::matched_index` reuses `PrintPayload::accepts`: the measured 56-byte
  reply shape, verdict `1`, and the print's own recorded handle. `Identify` composes one `Verify`
  whose type-2 array carries every candidate handle and sends exactly one `0x2F` (attr `0x47`).
  An empty gallery finishes at `start` with `EmptyGallery` and sends nothing.
- **Plugin.** `Plugin::identify_start` takes `(gallery index, fpi-data bytes)` pairs, runs one
  `Identify`, and stores the matched gallery position for `take_match`. A match keeps the session
  open and reports `Ok`; a no-match (verdict `0`, a handle outside the gallery, or an unusable
  gallery) reports `OutcomeKind::NoMatch` with no error and also keeps the session. A protocol or
  transport failure uses verification's mapping and completes as an error; a cancel tears down via
  `Verify` and completes as `Cancelled` with no match. The shim suppresses a match that completed
  after the client cancelled, as ticket 15 requires.
- **Shim.** C hands Rust one `Cv3GalleryEntry` per print: the `fpi-data` pointer, its length, and
  the print's gallery position. C does not decode a payload. The gallery is ref'd until the
  completion because `fpi_device_identify_report` only accepts a `match` pointer that is in the
  gallery libfprint owns; the report passes that exact `FpPrint`, never a copy. A no-match reports
  `(NULL, NULL, NULL)` and completes with no error; libfprint accepts an empty match.
- **Feature decision (EDGE CASE for the orchestrator).** The ticket's box asks for IDENTIFY to be
  declared only when prints are bound. `FpDeviceClass.features` is a static class mask and libfprint
  1.95 has no per-gallery feature bit; other drivers declare IDENTIFY unconditionally and let the
  caller supply the gallery. A dynamic mechanism would have to be invented
  (`fpi_device_update_features` toggling at print load time), which this ticket deliberately does
  not do. The honest option was chosen: the class declares `VERIFY | IDENTIFY`, the `identify`
  vfunc exists, and identification itself refuses an empty or unusable gallery by reporting no
  match (not an error and never a false match). The residual gap is that a client which inspects
  features sees IDENTIFY before any print is stored; its identify call then returns no match.
- **fprintd limitation.** fprintd 1.94 has no identification method on its D-Bus interface (only
  `VerifyStart`/`EnrollStart`), so identification cannot be exercised through fprintd on this
  machine. It is a libfprint-level capability. `scripts/identify-hardware.sh` is the hardware
  harness; it never runs sudo itself.

## What the hardware run must confirm

- That one `0x2F` with a type-2 array of two handles matches the presented enrolled finger and
  returns exactly one of those handles (the multi-handle array is unmeasured; only one-handle
  requests were measured on 2026-10-29).
- That an unenrolled finger answers verdict `0` and is reported as no match, and that a second
  user's finger identifies their own print and not the other's.
- That the match id in a print reloaded from fprintd's database still identifies after a restart.
- That a cancelled identification returns promptly and leaves the next operation usable (ticket 15's
  rules apply unchanged).

### Exact command

Build first (no root needed), then stop fprintd and run the harness as root:

```sh
./scripts/build-plugin.sh
./scripts/identify-hardware.sh                 # builds the harness and prints this command
sudo systemctl stop fprintd
sudo FP_TOD_DRIVERS_DIR="$PWD/target/identify-tod" \
     "$PWD/target/identify-hardware" --user "$USER"
```

The harness loads the plugin through `FP_TOD_DRIVERS_DIR` (a staged directory holding only
`libfprint-2-tod-1-cv3.so`), enumerates the device from `FpContext`, opens it, calls
`fp_device_identify_sync` with the gallery, and prints the matched print's finger, username and
description or `no match`. `--user` reads fprintd's own stored prints with
`fp_print_deserialize`; `--print FILE` reads one such file; `--payload HEX` builds a print from the
`print payload <hex>` line `cvctl enroll-then-verify` prints. Prefer `--user`: it is the same
serialized record fprintd loads, so it also checks the payload round trip. `--payload` exists for a
printer with no fprintd database and does not exercise fprintd's storage. Restart fprintd afterwards.

## Comments

2026-10-29, ticket 20 implementation:

- `fprintd` 1.94.5's D-Bus interface has no identification call (checked: only `VerifyStart` and
  `EnrollStart`), so the end-to-end path is a libfprint-level harness under `scripts/`.
- The class now declares `FP_DEVICE_FEATURE_VERIFY | FP_DEVICE_FEATURE_IDENTIFY` and sets
  `device_class->identify`; `scripts/check-tod-class.sh` pins both, and drives an empty and an
  unusable gallery through the real shim to prove the no-match completion and that no frame is
  written.
- Scripted tests cover: two bound prints matching the second; a handle outside the gallery;
  empty, unbound, foreign, malformed and duplicate-handle galleries; verdict `0`; a malformed reply;
  a transport failure at each of the seven stages; a cancel during the finger wait; and a session
  that stays usable after both a match and a no-match.
- The multi-handle request itself is still unmeasured on the sensor; that is what the hardware run
  above is for. The ticket's "declared only when prints are bound" box cannot be met in this ABI;
  the decision and its reasoning are in the implementation notes and are flagged to the
  orchestrator.

Measured on hardware 2026-10-29 with `scripts/identify-hardware` (fprintd 1.94 has no
identification call):

```text
gallery: 1 print(s)
  [0] finger=right-index-finger username=cristiano description=(none)
matched: [0] finger=right-index-finger username=cristiano description=(none)
```

Presenting the unenrolled left index answered `no match`. Still unmeasured: a gallery with two
prints on the sensor and a second user's print.

# Independent review — controlvault3-linux-fingerprint

Reviewer: automated code review session, 2026-10-28
Repository: https://github.com/japananimetime/controlvault3-linux-fingerprint
Commit reviewed: `a597fd3ff9bc4cb8a3d9496231daaf1916cf7c5d` (`master`, no tags)
Local clone: `tmp/cv3-review/` (scratch; safe to delete)
Licence: MIT
Size: 17 text files, 340 KB with `.git`, no binaries, no submodules, no LFS objects

## Scope

Everything in the tree was read: `driver/cvfp-tod.c` (585 lines, the file that would be
installed), `tools/cvchan.c`, `tools/cvrecover.c`, `pam/cvfp-verify.c`, `pam/pam_cvfp.c`,
`pam/install.sh`, `integrations/i3lock/cvlock`, `windows/cvhook.js`, all Markdown, plus the git
metadata.

## Provenance and trust signals

| Signal | Value | Assessment |
|---|---|---|
| Commit history | 17 commits, all on 2026-09-01 | One sitting, one author |
| Stars / forks / issues | 2 / 1 / 1 | No independent uptake |
| Releases / tags / CI | none | Nothing reproducible published |
| Binaries in repo | none | Good: what you build is what you read |
| Hidden hooks, LFS pointers, submodules | none | Clean |
| Non-ASCII / obfuscation / long encoded blobs | none (only em-dashes in prose) | Clean |

The prose reads like AI-assisted work and the validation claim ("Latitude 5531, libfprint-tod
1.94.8") is self-reported. Treat the code as unreviewed third-party code, not as a hardened
component.

## Hostile-behaviour audit

Scanned every file for process execution, networking, dynamic loading, environment access,
privilege changes, filesystem writes and suspicious paths.

- `driver/cvfp-tod.c`: **none**. No `system`/`popen`/`exec*`, no sockets, no `dlopen`, no
  `getenv`, no `setuid`, no file I/O, no `/etc`/`/home`/`ssh`/`shadow`/`tmp` references. Its only
  I/O is the USB device through libfprint transfers.
- `tools/*`: only `/sys/bus/usb/devices` (device `authorized` toggle, vendor/product ids read
  from sysfs) and `libusb`.
- `pam/*`: `fork`+`exec` of a helper path (PAM config, root-owned), `setuid` helper installed by
  `install.sh`, and edits to `/etc/pam.d/*` + `/etc/security/faillock.conf`.
- `windows/*`: Frida hooks against `ncrypt.dll`/`bcrypt.dll`, documentation only; nothing runs on
  Linux and no key material is stored in the repo.

No exfiltration path, no hidden payload, no anti-analysis tricks.

## Findings

### F1 — HIGH (privileged): unchecked reply length → stack overflow (patched here)

`cvfp_unwrap()` decrypts `rlen - 44` bytes into the caller's buffer:

```c
static int cvfp_unwrap (FpiDeviceCvfp *self, guint8 *pt){
  if (self->rlen < 44+16) return -1; int cl = self->rlen - 44; if (cl % 16) return -1;
  return cvfp_aes (self, 0, self->rb+24, self->rb+44, cl, pt);
}
```

`rlen` comes from the interrupt-reported reply length and is only capped at `sizeof self->rb`
(8192) by `tsc_int_cb()`. All three call sites pass `guint8 pt[512]` (lines 402, 461, 491), so a
device frame longer than 556 bytes overflows up to ~7.6 KB onto the stack **inside `fprintd`,
which runs as root**. Same defect exists in `tools/cvchan.c:219` and `pam/cvfp-verify.c:109`.

Trigger requires a device that answers with a long frame: a firmware fault, or a substituted USB
device spoofing `0a5c:5843` (the reader is soldered, so not a plug-in dongle). Low practical
likelihood, but it is an unchecked length in privileged C and trivially fixable.

Fixed in the local clone (see `notes/cvfp-tod-hardening.patch`):

```c
  if (cl > CVFP_MAX_PT) return -1;   /* 512: the callers' stack buffer */
```

### F2 — MEDIUM (design): verification trusts an unauthenticated device verdict

- Incoming replies are decrypted but their HMAC token is **not** verified (`cvfp_unwrap` only
  calls `cvfp_aes`), so replies are confidential but unauthenticated.
- `dev_verify` reports success solely from the word at plaintext `+8` of the `0x73` reply. The
  20-byte template id at `+32` is deliberately ignored, because it lives in a different id space
  than the enrol id.
- Consequence: fprintd's per-user binding is lost. If two users each enrol a finger, **either
  finger satisfies either user's verify**, because the chip only answers "did this match a
  template in my store?". A device that lies (or a spoofed device) can assert a match.

On a single-user laptop this is equivalent to the vendor stack's behaviour and is documented in
the repo (`ROADMAP.md`). On a shared machine it is a real weakness. It also means the channel is
not a trust boundary: its purpose is protocol acceptance, not security.

### F3 — MEDIUM (path B only): the standalone PAM installer is wrong on Debian/Ubuntu

`pam/install.sh` is only used by the *standalone* route, which is not the one we install. Still
worth recording, because it is actively harmful if anyone runs it here:

- It inserts the PAM line by matching `auth include system-auth`. Ubuntu's `/etc/pam.d/sudo` uses
  `@include common-auth`, and `/etc/pam.d/system-auth` does not exist, so **no PAM line is ever
  added** — while `systemctl mask fprintd` runs unconditionally. Result: fprintd masked *and* no
  working fingerprint prompt.
- It installs `cvfp-verify` setuid root (`-m4755`) — a bespoke setuid binary that opens the USB
  device and writes the device's `authorized` sysfs knob. Large attack surface for the benefit.
- It rewrites `/etc/pam.d/polkit-1` and deletes/overwrites `deny`/`unlock_time` in
  `/etc/security/faillock.conf` (system-wide lockout policy).

Recommendation: do not use path B. Path A changes exactly one file.

### F4 — LOW: unchecked lengths in `cvfp_build_wrapped` (patched here)

`macin[256]`, `pt[256]`, `ct[512]`, and the caller's `out[256]` are filled with `tlvlen`/`ptlen`
without validation. Every current caller passes constants that fit (max 172 bytes total), so it is
not exploitable today; it is a trap for the next edit. Added explicit guards; behaviour for all
existing callers is unchanged.

### F5 — LOW: unchecked allocations

`EVP_CIPHER_CTX_new()`, `BN_CTX_new()`, `BN_new()` results are not checked; a NULL would be
dereferenced. Only reachable under memory exhaustion.

### F6 — INFO: weak-but-adequate crypto for its purpose

`master = SHA1(ECDH_Z)`, `sessionKey = SHA1(master‖dn‖hn2)[:16]`, and a hardcoded
`macKey = SHA256("CV secure session blob\0")`. These are the chip's own constants, not user
secrets, and there is no key material from Windows in the repo. Given F2 the channel provides no
security guarantee anyway; do not describe it as one.

### F7 — INFO: documentation drift

`driver/README.md` still says "v2, in progress; next: verify/enroll", while `ROADMAP.md` and the
top-level README say the driver is done. Cosmetic.

## Correctness observations (not defects)

- Handshake bounds check is correct: the `0x23` reply must be ≥ 192 bytes, matching the reads at
  `+44` (64 bytes) and `+172` (20 bytes).
- SSM sequencing and the wrap-counter rules match `docs/secure-channel.md`; the retry paths
  (`0x85` capture pending, `0x0F` MAC reject) are handled.
- `tsc_in_cb` copies `actual_length` into `rb[8192]` after an IN transfer sized
  `min(reply_len, 8192)` — safe.
- No `cancel` vfunc is registered; cancellation relies on the device `GCancellable` aborting the
  finger-wait interrupt transfer. Consistent with the non-cancellable-command design; worth
  watching if fprintd `Cancel` ever appears to hang.
- Enrolment loop is bounded (`MAX_ENROLL_SAMPLES`), commit is guarded by a stage count.
- Feature set is `FP_DEVICE_FEATURE_VERIFY` only: `list`/`delete`/`identify` are absent by
  design; the chip keeps its templates even when fprintd drops the host record.

## Not verified here (must be checked at install time)

1. **It compiles against Ubuntu's libfprint 1.95.1+tod1.** `drivers_api.h` and the TOD headers
   come from `libfprint-2-tod-dev`, which is not installed. The repo was validated on 1.94.8.
2. **Symbol versioning.** All 24 libfprint functions used by the driver are exported by the
   installed `libfprint-2-tod.so.1`. `fpi_ssm_new` is a macro in the header; it must resolve to
   `fpi_ssm_new_full@LIBFPRINT_TOD_1_1.92`, not the unversioned/1.0.0 4-argument thunk. Verify
   with `readelf -sW` on the built `.so` before installing.
3. **Runtime behaviour on this exact unit** (Latitude 5430, kernel 7.2.6). Self-reported
   validation is on a different laptop, distro and libfprint.
4. **The wedge claims.** The recovery guidance (`authorized` toggle, never `libusb_reset_device`)
   is plausible and self-consistent, but was measured on the author's machine.

## Second independent pass — reconciliation

Two separate reviewers audited commit `a597fd3` without being told my conclusions: one for security
(malice, memory safety, privilege), one for correctness against the author's own documentation.
Neither was told the other's findings. This section records what changed as a result.

### Findings that outrank my original ones

- **F2 is an attack, not just a modelling weakness.** Replies are encrypted but unauthenticated,
  and the verdict is a plaintext word at `+8`. Because `P0 = D(C0) XOR IV` and the IV sits in
  cleartext at `+24`, flipping one bit of `IV[8]` rewrites that word. Verified locally:
  `0 -> 1` with a single XOR, no session key, no interaction with the device. My original wording
  ("a device that lies could assert a match") understated this — no lying device is needed, only
  the ability to modify one reply in flight.
- **F3 has a concrete escalation path**: a second user can run `fprintd-enroll` without root and
  then satisfy the first user's greeter/polkit prompt. It is a cross-account authentication
  failure on any shared machine, not a footnote about id spaces.
- **New: the 0x85 sequence disagreement.** `cvfp-tod.c:233-235` bumps the wrap counter after a
  `0x85` "capture pending" reply, while `cvchan.c:356-361` re-sends `0x66` at the *same* counter
  and increments only after a non-`0x85` success. Both cannot be right. The `0x85` path is exactly
  what a cancelled or timed-out capture produces, so it is the path a screen locker exercises. If
  the driver is wrong, every later wrapped command in that session fails with `0x0F`. Must be
  settled on hardware (cancel a verify mid-capture, then verify again).
- **New: no recovery machinery in the driver.** The SIGTERM/SIGINT/SIGHUP handlers and the
  `authorized`-toggle auto-recovery described in `README.md:121-128` exist only in
  `tools/cvchan.c` and `pam/cvfp-verify.c`. `driver/cvfp-tod.c` has neither, so a path-A user whose
  fprintd dies mid-capture gets the wedge and must toggle `authorized` by hand.
- **New: uninitialized bytes sent to the device.** `build_04_close()` left `+44..+47` unwritten;
  harmless on the normal close (an earlier frame zeroed that stack) but real on the open-failure
  teardown, where `TD_CANCEL` is skipped and nothing else writes the buffer. A root stack leak and
  a malformed TLV tag. Fixed here.
- **New: path B's `polkit-1` file is actively dangerous on Ubuntu.** `/etc/pam.d/polkit-1` does not
  exist; the vendor file is `/usr/lib/pam.d/polkit-1`. `install.sh` creates the former with
  `include system-auth`, which does not exist on Debian/Ubuntu. Linux-PAM treats a missing include
  as a must-fail action, and `/etc/pam.d` shadows `/usr/lib/pam.d` — so `pkexec`/polkit
  authentication, password path included, breaks. This is worse than "path B does nothing".

### Findings that stand

F1 (confirmed independently, rated Critical rather than High — fair), F4, F5, and the no-malice
conclusion: both reviewers found no network access, no persistence, no obfuscation, no credential
harvesting, and no binaries in the tree. The second reviewer additionally verified that the
libfprint API surface used compiles against the target's 1.95.1+tod1 headers, and that the
`fpi_device_open_complete()` leak the commit works around is real in that version.

### Documentation defects worth recording (from the correctness pass)

`docs/secure-channel.md:38` says a 24-byte device nonce (the code reads 20); the `0x04`/`0x68` row
at `:86` gives the wrong attr/encoding (`0x04` is sent with attr `0x40`, enc `0x04`); `:32-33`
says to always issue a bulk read even for `reply_len == 0`, which neither implementation does;
`0x8F` is accepted by both implementations but documented nowhere; `driver/README.md` still claims
enrol/verify are unimplemented; and "the GNOME/KDE panels all just work" oversells a driver with
`FP_DEVICE_FEATURE_VERIFY` only.

### Verdict after reconciliation

My first verdict ("safe to try with the patch") was too generous, and the second reviewer's "do not
install in this state" was too strict about path A. The defensible position:

- The **memory-safety class** is fixed for the driver, and now also for `cvfp-verify.c` and
  `cvchan.c` (same clamp, no protocol change). That removes the only remote-ish crash/RCE vector.
- What remains is **semantic**: the fingerprint proves "a finger in this chip's global store", not
  "this user". On this laptop — one human account, an internal soldered sensor — that is a
  convenience factor, and it is exactly what the proprietary blob gives. On a shared machine it is
  an authentication bypass, and no patch to this repo fixes it without the `0x2F` id mapping.
- **Path B must not be used**: broken and dangerous on Ubuntu, plus a setuid helper that needs the
  clamp it only just got.

So: path A only, patched, single-user, with the fingerprint treated as convenience and the password
kept as the real factor. And rebuild against 1.95.1, into the multiarch TOD directory — the
README's own install path does not exist on this system.


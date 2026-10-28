# controlvault3

A Linux driver project for the Dell/Broadcom **ControlVault 3** fingerprint sensor (BCM58200, USB
`0a5c:5843`): a Rust protocol core and probe, with a thin C shim planned for the libfprint TOD
interface.

Status: protocol probe. The Rust core speaks the sensor's ECDH handshake and secure session and
performs capture, enrolment and verification; `cvctl` drives it against the sensor directly. Still
missing: the libfprint TOD plugin (`crates/cv3-tod`, not built yet), binding a match to the print
that was enrolled (ticket 10), and the template inventory with list and delete. Until those land
this is a probe, not a login driver.

## What the probe can do

| Command | What it establishes |
|---|---|
| `devices` | Finds the sensor and prints its stable USB location. |
| `handshake` | Runs `0x23`/`0x24`, derives the session key and releases the handle. |
| `open` / `close` | Opens the wrapped `0x02` session and releases it with plain `0x04`. |
| `capture` | Arms `0x66`, waits for the finger, reads the sample hash and tears the session down. |
| `enroll` | Discards, starts, captures, submits, commits and prints the template id it now holds. |
| `enroll-then-verify` | Enrols and commits, then takes one confirmation touch and matches it in the **same session**. It is the ticket-09 measurement tool: it reports whether a match immediately after a commit works and what value comes back, and it is **not** a binding check. |
| `verify` | Captures and matches `0x73`, printing the raw verdict word, the 20-byte value and the reply lengths. |
| `cancel-then-verify` | Cancels a capture mid-session and verifies in the same session; it is the run that can settle the wrap-sequence question when the first arm answers `0x85`, and the current reading is unmeasured. |
| `handshake`/`open`/`close --record` | Writes a wire-only transcript; `cvctl replay <file>` reproduces it without hardware. |

## Layout

| Path | What it is |
|---|---|
| `crates/cv3-core` | Protocol core. Performs no I/O: events in, actions out. |
| `crates/cv3-probe` | `cvctl`, the probe used to establish protocol facts on hardware. |
| `crates/cv3-tod` | The libfprint TOD plugin: the C shim plus the Rust core it drives. Not built yet. |
| `docs/adr/` | Why the shape is what it is. |
| `docs/agents/` | Issue tracker, triage and domain-doc conventions for agents. |
| `GLOSSARY.md` | The project's vocabulary. Read it before naming anything. |

## Reference material (not part of the build)

`extracted/`, `*.deb` and `tmp/` hold the vendor blob, the downloaded packages and an audited
third-party C implementation; they are reference only, never built, never installed, and excluded
from the crates and from git. `notes/` is tracked reference material — the audit of that
implementation and extracted strings — and is likewise not part of the build.

`*.cvrec` files written by `cvctl ... --record` are local recordings of one real session. They
are **wire-only**: handshake, open and close only, storing the frames as they went on the wire but
not the host secret key or any separate session material. Replay uses a fresh ephemeral host key,
so frames match on command, attribute and handle rather than byte for byte. A recording still
contains real device traffic, so `.gitignore` keeps `*.cvrec` out of git. Committed fixtures are
synthetic and built from the frame codec; `cvctl replay <file>` reproduces a recording without
hardware. `verify` has no `--record`: a match reply cannot be decrypted on replay without storing
the session's key material, which the SPEC forbids.

## Building

```sh
cargo test          # whole workspace; no hardware needed
cargo build --release
```

The probe drives the sensor through the kernel's USB device nodes and therefore runs as root.
`cv3-tod` additionally needs `libfprint-2-tod-dev`.

`./scripts/check-core.sh` mechanically checks that the core's direct dependencies are only the
pinned crypto set and that its source contains no `unsafe`; the GitHub workflow runs it alongside
formatting, clippy, the workspace tests, and `cargo-deny` for RustSec advisories and licences
(`deny.toml`).

## `cvctl` exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | any error without a more specific code, including a usage line |
| 2 | sensor `0a5c:5843` not found |
| 3 | sensor busy: another process holds interface 0 |
| 4 | permission denied opening the sensor |
| 5 | the sensor rejected the wrap sequence (`0x0F`) |
| 6 | a replay diverged from its transcript |
| 7 | a capture arm answered `0x85`: a capture was already armed; the session was torn down |
| 8 | a finger wait timed out; the session was torn down |
| 9 | `verify` completed with a genuine no-match; this is a result, not an error |
| 10 | a transport failure during a command operation; distinct from a finger timeout |
| 128 + signal | interrupted by a catchable signal (for example 130 for `SIGINT`) |

`capture` prints the sample hash on success and always runs the cancel-then-close teardown before
exiting. `verify` prints the raw verdict word with its meaning (`verdict 1 (match)`,
`verdict 2 (no match, unexpected word)`), the 20-byte value (or `value absent`), the raw reply
length and the decrypted plaintext length, then runs the same teardown. The value's meaning is not
established, and `verify` does not yet compare it with anything: ticket 10 owns id binding.

`cvctl enroll-then-verify` is the ticket-09 measurement tool: it enrols and commits, prints the
template id and its source, then takes one more touch and runs `0x73` in the **same secure
session**, printing the verdict the way `verify` does. It answers whether a capture and match
immediately after a commit are accepted and what value that reply carries. It deliberately does
not compare the value with the enrolment id — ticket 10 owns binding — so a match here proves only
that the sensor matched some enrolled template.

`cvctl cancel-then-verify` owns one session and runs the sequence that can settle the wrap-sequence
question: it arms a capture, cancels it with the mid-session `0x68` before any finger, then runs a
full verification in the same session and prints its verdict the way `verify` does. An arm that
answers `0x85` is consumed, cancelled and re-armed, which is the case the two readings of the rule
disagree about; the current reading is still unmeasured, and the run settles it only when that
`0x85` case actually occurs. See `docs/protocol-notes.md`.

`handshake --show-key` adds the derived session key to the ordinary report. Without the flag only
its short fingerprint is printed, because the key is freshly generated for the run and sensitive.

`--hex` on `handshake`, `open`, `close`, `capture`, `enroll`, `enroll-then-verify`, `verify` and
`cancel-then-verify`
writes every host frame and every device reply body to **stderr** as lowercase hex, prefixed `> `
and `< ` (`< empty` for a reply with no body, `< finger` for the finger event). The decoded output
on stdout is unchanged. The flag is a transport wrapper over the core's `Transport` seam, so no
operation changes.

A catchable signal (`SIGINT`, `SIGTERM`, `SIGHUP`) during the finger wait cancels that transfer,
tears the session down (`0x68`, then `0x04`) and exits `128 + signal`; command transfers are never
cancelled. `docs/recovery.md` is the operator's ladder for a sensor that an external kill did wedge.

## Documentation

| Path | What it is |
|---|---|
| `docs/protocol-notes.md` | Protocol facts: what was measured, what is only read from the reference, and the wrap-sequence question. |
| `docs/recovery.md` | The recovery ladder for a wedged sensor, and what the driver does on failure. |
| `GLOSSARY.md` | The project's vocabulary. Read it before naming anything. |

## Licence

MIT. See `NOTICE` for attribution: the protocol was reverse-engineered by others, and their
write-up is the source of the constants in `crates/cv3-core/src/proto.rs`.

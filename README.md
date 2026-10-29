# controlvault3

A Linux driver project for the Dell/Broadcom **ControlVault 3** fingerprint sensor (BCM58200, USB
`0a5c:5843`): a Rust protocol core and probe, with a thin C shim for the libfprint TOD interface.

Status: protocol probe plus an enumeration-only libfprint TOD plugin. The Rust core speaks the
sensor's ECDH handshake and secure session and performs capture, enrolment and verification;
`cvctl` drives it against the sensor directly. `crates/cv3-tod` makes the sensor appear to
`fprintd` as a reader but opens no session yet. Still missing: the plugin's session and operations,
binding a match to the print that was enrolled (ticket 10), and the template inventory with list
and delete. Until those land this is a probe, not a login driver.

## What the probe can do

| Command | What it establishes |
|---|---|
| `devices` | Finds the sensor and prints its stable USB location. |
| `handshake` | Runs `0x23`/`0x24`, derives the session key and releases the handle. |
| `open` / `close` | Opens the wrapped `0x02` session and releases it with plain `0x04`. |
| `capture` | Arms `0x66`, waits for the finger, reads the sample hash and tears the session down. `--hex` also prints the decrypted arm reply: its lengths, hex rows and TLV scan. |
| `inventory` | Sends the wrapped `0x2F` inventory query and dumps its reply: the raw and plaintext lengths, the plaintext in 16-byte rows and a best-effort TLV scan. It is the ticket-16 measurement tool and does not yet decode the reply. |
| `enroll` | Discards, starts, captures, submits, commits and prints the template id it now holds. `--commit-sample-hash` forces the last sample hash into the commit; `--show-commit` prints the decrypted `0x6E` reply, its lengths and TLV scan. |
| `enroll-then-verify` | Enrols and commits, then takes one confirmation touch and matches it in the **same session**. It is the ticket-09 measurement tool: it reports whether a match immediately after a commit works and what value comes back, and it is **not** a binding check. `--commit-sample-hash` forces the last sample hash into the commit and the confirmation match; `--show-commit` dumps the commit reply; `--handle` adds `u32` template handles. When the commit reply names a handle, the confirmation matches it with `0x2F` and the probe prints the bound print payload it would store. |
| `verify` | Captures and sends the vendor's identify: **`0x2F`** by default (no hash, matches the `u32` handle array) and **`0x73`** when `--template` supplies a hash. Prints the command sent, the raw status, the verdict word, the matched template handle, the reply lengths and the decrypted plaintext with a TLV scan. `--template <40 hex>` adds the optional `(3,20,hash)` entry; `--handle` adds `u32` template handles to the one-to-many array and enables the binding check (`binding accepted` only when the reply carries that exact id); `--command 72` sends the one-to-one verify instead. |
| `cancel-then-verify` | Cancels a capture mid-session and verifies in the same session; it is the run that can settle the wrap-sequence question when the first arm answers `0x85`, and the current reading is unmeasured. |
| `handshake`/`open`/`close --record` | Writes a wire-only transcript; `cvctl replay <file>` reproduces it without hardware. |

## Layout

| Path | What it is |
|---|---|
| `crates/cv3-core` | Protocol core. Performs no I/O: events in, actions out. |
| `crates/cv3-probe` | `cvctl`, the probe used to establish protocol facts on hardware. |
| `crates/cv3-tod` | The libfprint TOD plugin: the C shim plus the Rust crate, enumeration only. |
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
cargo test               # core and probe; no headers and no hardware needed
cargo build --release
cargo test --workspace   # adds the TOD plugin; needs libfprint-2-tod-dev
```

The probe drives the sensor through the kernel's USB device nodes and therefore runs as root.
`cv3-tod` additionally needs `libfprint-2-tod-dev` (headers), `pkg-config` and a C compiler; it is
a workspace member but not a default one, so the core and the probe build without them.

`./scripts/check-core.sh` mechanically checks that the core's direct dependencies are only the
pinned crypto set and that its source contains no `unsafe`; the GitHub workflow runs it alongside
formatting, clippy, the workspace tests, and `cargo-deny` for RustSec advisories and licences
(`deny.toml`).

## The TOD plugin

`crates/cv3-tod` builds `libcv3_tod.so`, a libfprint TOD driver. At this milestone it only makes
the sensor appear to `fprintd` as a reader: the class id is `cv3`, the full name names the
Dell/Broadcom ControlVault 3, the id table matches `0a5c:5843`, the scan type is press, and the
probe completes without touching USB. No session, enrol or verify exists yet and the device
advertises no feature, so clients list the reader but cannot claim or open it: `fp_device_open`
fails with `NOT_SUPPORTED` and `fprintd` stays up. Claiming and the operations arrive with
ticket 12.

```sh
./scripts/build-plugin.sh      # cargo build, then a check of the TOD symbol versions
./scripts/install-plugin.sh    # build, then copy one .so into the TOD drivers directory
./scripts/uninstall-plugin.sh  # delete that one file
```

Installing adds `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod-1-cv3.so` and
nothing else: no `libfprint` or `fprintd` configuration is touched. Neither script runs `sudo`;
without write access they print the exact command to run as root, with the paths quoted. If the
TOD drivers directory does not exist yet, `install-plugin.sh` prints the `sudo install -d` command
that creates it. Remove any other TOD driver that claims `0a5c:5843` first, since only one driver
can own the reader; that is also a single file. A relative `CV3_TOD_DIR` is resolved against the
directory you run the script from.

`./scripts/check-tod-link.sh` (run by `build-plugin.sh`) inspects the built object with
`readelf -sW` and fails when a `fpi_*` import is unversioned or binds a version older than the
library's default. That is the trap where `fpi_ssm_new_full` silently binds the legacy 4-argument
`@LIBFPRINT_TOD_1.0.0` thunk and crashes `fprintd` inside `fp_device_open`.

Verify, after installing and restarting the daemon (`sudo systemctl restart fprintd`):

```sh
fprintd-list "$USER"     # reports the cv3 reader (with no prints enrolled)
fprintd-enroll "$USER"   # must fail cleanly with NOT_SUPPORTED and leave fprintd running
```

Uninstall by deleting the one file (`./scripts/uninstall-plugin.sh`, or `sudo rm` with the path it
prints) and restarting `fprintd`.

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

`capture` prints the sample hash on success (and, with `--hex`, the decrypted arm reply) and always runs the cancel-then-close teardown before
exiting. `verify` sends `0x73`, the vendor's one-to-many identify: the request is the parameter
list measured from `cv_do_fingerprint_identify` — `(0,4,handle)`, `(0,4,0x48)`, `(0,4,0x53e2)`,
`(0,4,0)`, `(2,4*count,handles…)` and, only with `--template`, `(3,20,hash)`. `--handle` supplies
`u32` template handles (decimal or `0x` hex, repeatable or comma-separated); with no handle the
type-2 entry is size zero and the sensor matches every stored template. `--command 72` sends the
one-to-one `cv_do_fingerprint_verify` instead. The decode prints the command actually sent and the
raw reply status (`0x00` or the `0x89` the vendor special-cases), then the verdict word with its
meaning (`verdict 1 (match)`, `verdict 2 (no match, unexpected word)`), the matched handle (or
`value absent`), the raw reply length and the decrypted plaintext length, and then the decrypted
plaintext in 16-byte hex rows with a `type=… len=… value=…` TLV scan. A refused request prints the
same command/status/length dump so a `0x0E` that still carried a body is visible. The verdict still
comes from the decoded body, whatever the status. The value's meaning is not established, and
`verify` does not yet compare it with anything: ticket 10 owns id binding.

`cvctl enroll-then-verify` is the ticket-09 measurement tool: it enrols and commits, prints the
template id and its source, then takes one more touch and sends the match request in the **same
secure session**, printing the command, status, verdict and plaintext dump the way `verify` does.
Its default is `0x73`; `--command 72` swaps in the one-to-one verify. `--handle` adds template
handles to the composed match. It answers whether a capture and match immediately after a commit
are accepted and what value that reply carries. It deliberately does not compare the value with the
enrolment id — ticket 10 owns binding — so a match here proves only that the sensor matched some
enrolled template.

`--show-commit` on `enroll` and `enroll-then-verify` prints the decrypted `0x6E` commit reply: the
raw reply length, the plaintext length, 16-byte hex rows and the TLV scan. The vendor's commit
saves its reply through an out list of a type-3 blob and a type-0 `u32`; that `u32` is the template
handle identify later names, so this is the measurement tickets 06/07/09/20 need. Recordings stay
wire-only: the plaintext is printed, never recorded.

`cvctl inventory` is ticket 16's first step: it reports the two lengths, the decrypted plaintext
and a best-effort TLV scan of the `0x2F` reply, without assuming the reply lists stored templates.
Whether the command reports anything about stored templates at all is still unestablished. It is a
measurement tool, not shipping behaviour.

`--commit-sample-hash` on `enroll` and `enroll-then-verify` commits with the last submitted sample
hash even when the sensor's `0x6C` reply carried an enrolment id, and labels the source as forced.
Ticket 06 has not established which id the sensor wants in the `0x6E` commit, so this is a
measurement variant, not shipping behaviour; without the flag the commit uses the sensor's
enrolment id as before. `--show-commit`, `--handle` and `--command` are measurement tools for
tickets 06, 07, 09 and 20; they change what the probe sends and prints, not what the driver will
ship.

`cvctl cancel-then-verify` owns one session and runs the sequence that can settle the wrap-sequence
question: it arms a capture, cancels it with the mid-session `0x68` before any finger, then runs a
full verification in the same session and prints its verdict the way `verify` does. An arm that
answers `0x85` is consumed, cancelled and re-armed, which is the case the two readings of the rule
disagree about; the current reading is still unmeasured, and the run settles it only when that
`0x85` case actually occurs. See `docs/protocol-notes.md`.

`handshake --show-key` adds the derived session key to the ordinary report. Without the flag only
its short fingerprint is printed, because the key is freshly generated for the run and sensitive.

`--hex` on `handshake`, `open`, `close`, `capture`, `inventory`, `enroll`, `enroll-then-verify`,
`verify` and `cancel-then-verify`
writes every host frame and every device reply body to **stderr** as lowercase hex, prefixed `> `
and `< ` (`< empty` for a reply with no body, `< finger` for the finger event). The host timestamp
request the sensor can raise on interrupt type 5 is answered in the USB transport; it has no bulk
frame, so the dump shows it as `* timestamp <packed:08x>`. It is sent only when the sensor asks:
the host never volunteers it before a command. The decoded output on stdout is unchanged. The flag is a transport wrapper over the core's
`Transport` seam, so no operation changes.

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

# controlvault3

A Linux driver for the Dell/Broadcom **ControlVault 3** fingerprint sensor (BCM58200, USB
`0a5c:5843`), written in Rust with a thin C shim for the libfprint TOD interface.

Status: scaffolding. Nothing here talks to the sensor yet.

## Layout

| Path | What it is |
|---|---|
| `crates/cv3-core` | Protocol core. Performs no I/O: events in, actions out. |
| `crates/cv3-probe` | `cvctl`, the probe used to establish protocol facts on hardware. |
| `crates/cv3-tod` | The libfprint TOD plugin: C shim plus Rust core wrapper. Not built yet. |
| `docs/adr/` | Why the shape is what it is. |
| `docs/agents/` | Issue tracker, triage and domain-doc conventions for agents. |
| `GLOSSARY.md` | The project's vocabulary. Read it before naming anything. |

## Reference material (not part of the build)

`extracted/`, `*.deb`, `tmp/` and `notes/` hold the vendor blob, the downloaded packages, an audited
third-party C implementation and the audit of it. They are reference only: never built, never
installed, excluded from the crates and from git.

`*.cvrec` files written by `cvctl ... --record` are local recordings of one real session. A
`cvctl verify --record` file additionally carries the run's ephemeral host key, nonces and IVs so
that the wrapped match reply can be replayed exactly; it is sensitive and must not be committed.
`.gitignore` keeps `*.cvrec` out of git. Committed fixtures are synthetic and built from the frame
codec; `cvctl replay <file>` reproduces a recording without hardware.

## Building

```sh
cargo test          # core only; the probe needs no hardware yet
cargo build --release
```

The probe drives the sensor through the kernel's USB device nodes and therefore runs as root.
`cv3-tod` additionally needs `libfprint-2-tod-dev`.

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
| 7 | `capture` found a capture already armed (`0x85`); the session was torn down |
| 8 | `capture` (or `verify`) timed out waiting for the finger; the session was torn down |
| 9 | `verify` completed with a genuine no-match; this is a result, not an error |
| 10 | a transport failure during a command operation; distinct from a finger timeout |
| 128 + signal | interrupted by a catchable signal (for example 130 for `SIGINT`) |

`capture` prints the sample hash on success and always runs the cancel-then-close teardown before
exiting. `verify` prints `match` or `no match`, the 20-byte value (or `value absent`), the raw reply
length and the decrypted plaintext length, then runs the same teardown. The value's meaning is not
established, and `verify` does not yet compare it with anything: ticket 10 owns id binding.

`cvctl cancel-then-verify` owns one session and runs the sequence that settles the wrap-sequence
question: it arms a capture, cancels it with the mid-session `0x68` before any finger, then runs a
full verification in the same session and prints its verdict the way `verify` does. An arm that
answers `0x85` is consumed, cancelled and re-armed, which is the case the two readings of the rule
disagree about. See `docs/protocol-notes.md`.

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

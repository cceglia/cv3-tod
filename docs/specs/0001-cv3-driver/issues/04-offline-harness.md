# 04: Offline harness

**What to build:** a session seen once on hardware becomes a test that runs anywhere: a scripted
sensor that can produce any reply sequence, and recording and replay of a real one.

**Blocked by:** 03 (secure session)

**Status:** done

- [x] A scripted-sensor transport drives the core through an arbitrary reply sequence, a finger event,
      a cancellation and a transport error, and is what the core tests use.
- [x] The same contract tests — reply, empty reply, error, cancellation, timeout — run against the
      scripted, replay and failure-injecting transports.
- [x] `cvctl` records a session to a file and replays it, reproducing the same outcome with no
      hardware attached (measured 2026-10-29: same handle and nonce lengths; a fresh host key, so the
      key fingerprint differs by design and the note says so).
- [x] The frame parser has a fuzz target that finds no panics across random and structured buffers
      (run 2026-10-30: `cargo +nightly fuzz run frame_parser -- -max_total_time=60 -runs=200000`,
      200000 runs, no crash).
- [x] Fixtures committed to the repository are synthetic and contain no real sensor material; raw
      captures stay out of version control (`git ls-files '*.cvrec'` is empty; the recording lives in
      `/tmp`).

## Comments

Implemented in 43cc49d; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Scripted, replay and
failure-injecting transports share one contract suite; recording is wire-only (handshake, open,
close) and replay needs no hardware. The deterministic no-panic corpus runs in `cargo test`. The
libFuzzer target is committed (`fuzz/fuzz_targets/frame_parser.rs`) but was **not executed**: it
needs `cargo +nightly fuzz run frame_parser`, which this environment cannot run. That box stays
unticked until someone runs it.

Hardware: `sudo ./target/debug/cvctl handshake --record /tmp/h.cvrec`, then
`./target/debug/cvctl replay /tmp/h.cvrec`.

The fuzz target was run on 2026-10-30 after installing a user-level nightly toolchain and
`cargo-fuzz` under `~/.cargo` (system Rust untouched): 200000 runs, 311 coverage edges, no crash
and no artifact. The generated corpus and artifacts stay untracked.

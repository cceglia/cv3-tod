# I/O-free Rust core behind a thin C shim

The driver must be a GObject subclass loaded by `fprintd`, an ABI that exists only in C, so the
plugin keeps a small C shim while every piece of protocol logic lives in a Rust core that performs
no I/O: the shim runs the USB transfers and hands the core events, and the core returns the next
action. Parsing, cryptography and session state therefore live in memory-safe code that can be
tested against recorded frames without hardware, while the unavoidable GObject plumbing stays in
the language that defines it.

## Considered Options

- **All-Rust plugin** (`glib-rs` subclassing libfprint's C types): rejected — it reimplements the
  same ABI with no safety gain and breaks on every libfprint TOD version bump.
- **Rust owning USB inside the plugin** (`nusb` over the `GUsbDevice` fd): rejected — it fights
  libfprint's claim on the interface and drags a second async model into the GLib main loop.

## Consequences

- A protocol change touches `cv3-core` only; the shim stays small enough to audit in one sitting.
- The same core drives both `cvctl` (probe, `nusb` transport) and the plugin (libfprint transport),
  so hardware findings are reproduced in the shipping code rather than rediscovered.
- The core's dependency list must never contain a transport crate; that is what keeps the boundary
  a compile-time fact rather than a convention.

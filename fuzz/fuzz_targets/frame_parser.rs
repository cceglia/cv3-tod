#![no_main]

//! Feeds arbitrary bytes to every parser that accepts device or transcript bytes.
//!
//! Run with `cargo +nightly fuzz run frame_parser`. The deterministic counterpart lives in
//! `crates/cv3-core/tests/no_panic.rs` so the ordinary test suite covers the same parsers.

use cv3_core::frame::{self, Header};
use cv3_core::session::SessionKey;
use cv3_core::transcript::Transcript;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Header::parse(data);
    let _ = frame::validate(data);

    // A wrapped reply is the one reply path that decrypts device bytes. A fixed key is enough:
    // the point is that no length or padding the device chooses can panic.
    let key = SessionKey::from_bytes([0x42; 16]);
    let _ = key.unwrap(data);

    // The decrypted capture reply is scanned for the sample hash; it is device-controlled too.
    let _ = cv3_core::capture::find_tlv_value(data, 20);

    // The replay parser reads a file, which is also untrusted input.
    let _ = Transcript::from_bytes(data);
});

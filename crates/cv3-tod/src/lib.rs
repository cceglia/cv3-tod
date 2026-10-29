//! `cv3-tod`: the libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor.
//!
//! The crate is a `cdylib` made of two layers. `shim/cv3_tod.c` owns the GObject side — the
//! `FpDevice` subclass, its class info and its vfuncs — and this crate exports the single symbol
//! `libfprint`'s TOD loader resolves. From the session ticket on, the shim's vfuncs call Rust
//! functions that own the protocol core: the C side hands over an event and receives the action
//! to perform, so no parsing, length arithmetic, cryptography or session state ever lives in C.
//!
//! Ticket 11 is enumeration only: the probe completes without touching USB, nothing here talks to
//! the sensor yet, and the vfuncs libfprint dereferences unconditionally fail cleanly. A failed
//! open releases the GUsb handle libfprint opened for it, so the reader stays available to the next
//! Claim.
//!
//! # Tests
//!
//! The C shim is not unit-tested from Rust: text assertions on its source pass whether the code
//! works or not, and cannot see what libfprint actually dereferences. Instead
//! `scripts/check-tod-class.sh` loads the built object, reads the live class, and drives the open
//! path under a fake for gusb — the behaviour this milestone promises. The tests here keep the
//! identity the two sides share, plus the exported symbol's name.

#![deny(unsafe_code)]

pub mod identity;

// The export links the C shim; unit tests pin the shim's declarations as text and do not link it,
// so the test binary stays a plain Rust binary.
//
// `unsafe` is confined to that module: an `extern` block and an `export_name` are the minimum the
// C boundary needs, and no protocol code goes here.
#[cfg(not(test))]
#[allow(unsafe_code)]
pub mod ffi;

#[cfg(test)]
mod tests {
    use crate::identity::{CLASS_ID, DEVICE_NAME, ENTRY_POINT, FULL_NAME, PRODUCT_ID, VENDOR_ID};

    /// The identity header `build.rs` generates for the shim.
    const IDENTITY_HEADER: &str = include_str!(concat!(env!("OUT_DIR"), "/cv3_tod_identity.h"));
    /// The Rust half of the boundary, for the entry point's name.

    #[test]
    fn claims_the_sensor_the_core_names() {
        // Facts from the SPEC, not recomputed from the code under test.
        assert_eq!(VENDOR_ID, 0x0a5c);
        assert_eq!(PRODUCT_ID, 0x5843);
    }

    #[test]
    fn identity_is_the_one_the_spec_names() {
        assert_eq!(CLASS_ID, "cv3");
        assert_eq!(FULL_NAME, "Dell/Broadcom ControlVault 3 fingerprint");
        // `fprintd-list` prints the device name, which comes from the probe's completion.
        assert_eq!(DEVICE_NAME, "Dell/Broadcom ControlVault 3");
    }

    #[test]
    fn the_generated_header_defines_the_identity_once() {
        for (macro_name, value) in [
            ("CV3_TOD_CLASS_ID", CLASS_ID),
            ("CV3_TOD_FULL_NAME", FULL_NAME),
            ("CV3_TOD_DEVICE_NAME", DEVICE_NAME),
        ] {
            assert!(
                IDENTITY_HEADER.contains(&format!("#define {macro_name} \"{value}\"")),
                "the generated header should define {macro_name} as {value:?}"
            );
        }
    }

    #[test]
    fn entry_point_is_the_one_libfprint_looks_for() {
        // The symbol's name is identity; that the built object really exports it, and that the
        // class behind it is sound, is what scripts/check-tod-class.sh checks.
        assert_eq!(ENTRY_POINT, "fpi_tod_shared_driver_get_type");
    }
}

//! `cv3-tod`: the libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor.
//!
//! The crate is a `cdylib` made of two layers. `shim/cv3_tod.c` owns the GObject side — the
//! `FpDevice` subclass, its class info and its vfuncs — and this crate exports the single symbol
//! `libfprint`'s TOD loader resolves. The shim's vfuncs call the Rust functions in [`ffi`], which
//! own the protocol core and return one action per step: an OUT / interrupt / bulk-in / control
//! transfer to perform, or a finish with a status, an error kind and a message. No parsing, length
//! arithmetic, cryptography or session state lives in C.
//!
//! Opening a device runs the `0x23`/`0x24` handshake and the wrapped `0x02` open through the same
//! I/O-free core the probe uses; closing sends the plain `0x04`. A failed open releases the GUsb
//! handle libfprint opened and destroys the Rust state, so the next Claim starts clean and no
//! session handle is left on the sensor. [`plugin`] is the session state machine and [`secret`]
//! draws the per-session key material.
//!
//! # Tests
//!
//! The C shim is not unit-tested from Rust: text assertions on its source pass whether the code
//! works or not, and cannot see what libfprint actually dereferences. Instead
//! `scripts/check-tod-class.sh` loads the built object, reads the live class, and drives a whole
//! failed-then-successful Claim and Release under a fake for gusb and for `fpi_usb_transfer_submit`.
//! The Rust tests here cover the session step machine against scripted transfers, plus the action
//! layout and message handling the two sides share.

#![deny(unsafe_code)]

pub mod identity;
pub mod plugin;
pub mod secret;

// `unsafe` is confined to that module: an `extern` block and the raw buffer ownership are the
// minimum the C boundary needs, and no protocol code goes here. The module compiles under tests
// too, with only the symbol export and the shim's extern block gated out, so the action layout and
// message handling are tested without linking the C shim.
#[allow(unsafe_code)]
pub mod ffi;

#[cfg(test)]
mod tests {
    use crate::identity::{CLASS_ID, DEVICE_NAME, ENTRY_POINT, FULL_NAME, PRODUCT_ID, VENDOR_ID};

    /// The identity header `build.rs` generates for the shim.
    const IDENTITY_HEADER: &str = include_str!(concat!(env!("OUT_DIR"), "/cv3_tod_identity.h"));

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

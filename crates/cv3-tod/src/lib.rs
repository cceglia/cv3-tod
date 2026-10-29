//! `cv3-tod`: the libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor.
//!
//! The crate is a `cdylib` made of two layers. `shim/cv3_tod.c` owns the GObject side — the
//! `FpDevice` subclass, its class info and its vfuncs — and this crate exports the single symbol
//! `libfprint`'s TOD loader resolves. From the session ticket on, the shim's vfuncs call Rust
//! functions that own the protocol core: the C side hands over an event and receives the action
//! to perform, so no parsing, length arithmetic, cryptography or session state ever lives in C.
//!
//! Ticket 11 is enumeration only: the probe completes without touching USB and nothing here talks
//! to the sensor yet.
//!
//! # Tests
//!
//! The C shim is not unit-tested, by decision in the SPEC: a GObject subclass needs a fake
//! `libfprint` harness, and keeping the shim free of logic is what makes that acceptable. The
//! tests here instead pin the facts the shim declares to the Rust side, as source text, so the two
//! declarations cannot drift apart silently.

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
    use crate::identity::{CLASS_ID, ENTRY_POINT, FULL_NAME, PRODUCT_ID, VENDOR_ID};

    /// The shim, as the C compiler sees it.
    const SHIM: &str = include_str!("../shim/cv3_tod.c");
    /// The Rust half of the boundary, for the entry point's name.
    const FFI: &str = include_str!("ffi.rs");

    #[test]
    fn claims_the_sensor_the_core_names() {
        // Facts from the SPEC, not recomputed from the code under test.
        assert_eq!(VENDOR_ID, 0x0a5c);
        assert_eq!(PRODUCT_ID, 0x5843);
    }

    #[test]
    fn shim_is_a_usb_press_reader() {
        assert!(SHIM.contains("device_class->type = FP_DEVICE_TYPE_USB;"));
        assert!(SHIM.contains("device_class->scan_type = FP_SCAN_TYPE_PRESS;"));
    }

    #[test]
    fn shim_binds_the_same_usb_ids() {
        let entry = format!("{{ .vid = {VENDOR_ID:#06x}, .pid = {PRODUCT_ID:#06x} }}");

        assert!(
            SHIM.contains(&entry),
            "the shim's id_table should contain `{entry}`"
        );
        assert_eq!(
            SHIM.matches(".vid = 0x0a5c").count(),
            1,
            "the plugin claims one sensor, not a family"
        );
        assert!(
            SHIM.contains("{ .vid = 0, .pid = 0 },"),
            "the id_table needs its terminator"
        );
    }

    #[test]
    fn shim_declares_the_class_identity_the_rust_side_names() {
        assert!(
            SHIM.contains(&format!("device_class->id = \"{CLASS_ID}\";")),
            "the shim's class id should be {CLASS_ID}"
        );
        assert!(
            SHIM.contains(&format!("device_class->full_name = \"{FULL_NAME}\";")),
            "the shim's full_name should be {FULL_NAME}"
        );
    }

    #[test]
    fn shim_starts_with_a_placeholder_feature_and_withdraws_it() {
        // libfprint asserts in fp_device_constructed that a class advertises some feature, so a
        // class with none aborts fprintd. The API must still report none until an operation exists.
        assert!(SHIM.contains("device_class->features = FP_DEVICE_FEATURE_CAPTURE;"));
        assert!(SHIM.contains(
            "fpi_device_update_features (device, FP_DEVICE_FEATURE_CAPTURE, FP_DEVICE_FEATURE_NONE);"
        ));
        assert!(SHIM.contains("device_class->probe = cv3_tod_probe;"));
    }

    #[test]
    fn shim_implements_no_operation_yet() {
        for vfunc in [
            "device_class->open",
            "device_class->close",
            "device_class->enroll",
            "device_class->verify",
            "device_class->capture",
            "device_class->identify",
            "device_class->list",
            "device_class->delete",
        ] {
            assert!(
                !SHIM.contains(vfunc),
                "enumeration only: `{vfunc}` belongs to a later ticket"
            );
        }
    }

    #[test]
    fn probe_completes_without_touching_usb() {
        assert!(SHIM.contains("fpi_device_probe_complete (device, NULL,"));
        assert!(
            !SHIM.contains("fpi_device_get_usb_device"),
            "probe must not open or claim the sensor"
        );
    }

    #[test]
    fn entry_point_is_the_one_libfprint_looks_for() {
        assert_eq!(ENTRY_POINT, "fpi_tod_shared_driver_get_type");
        assert!(
            FFI.contains(&format!("export_name = \"{ENTRY_POINT}\"")),
            "the exported symbol should be {ENTRY_POINT}"
        );
        assert!(
            FFI.contains("cv3_tod_shim_get_type"),
            "the entry point should forward to the shim's GType getter"
        );
    }

    #[test]
    fn shim_is_gobject_plumbing_only() {
        for forbidden in [
            "fpi_usb_transfer",
            "fpi_ssm",
            "g_usb_",
            "memcpy",
            "malloc",
            "<openssl/",
            "<string.h>",
            "<stdio.h>",
        ] {
            assert!(
                !SHIM.contains(forbidden),
                "the shim must contain no parsing, transfer, arithmetic or crypto API: found `{forbidden}`"
            );
        }
    }
}

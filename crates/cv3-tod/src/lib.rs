//! `cv3-tod`: the libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor.
//!
//! The crate is a `cdylib` made of two layers. `shim/cv3_tod.c` owns the GObject side — the
//! `FpDevice` subclass, its class info and its vfuncs — and this crate exports the single symbol
//! `libfprint`'s TOD loader resolves. From the session ticket on, the shim's vfuncs call Rust
//! functions that own the protocol core: the C side hands over an event and receives the action
//! to perform, so no parsing, length arithmetic, cryptography or session state ever lives in C.
//!
//! Ticket 11 is enumeration only: the probe completes without touching USB, nothing here talks to
//! the sensor yet, and the vfuncs libfprint dereferences unconditionally fail cleanly.
//!
//! # Tests
//!
//! The C shim is not unit-tested, by decision in the SPEC: a GObject subclass needs a fake
//! `libfprint` harness, and keeping the shim free of logic is what makes that acceptable. The
//! tests here instead pin the facts the shim declares — its class identity, the vfuncs libfprint
//! dereferences without a guard, and the shape of the escape hatches — as source text, so the
//! declarations cannot drift from the Rust side silently.

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
    /// The identity header `build.rs` generates for the shim.
    const IDENTITY_HEADER: &str = include_str!(concat!(env!("OUT_DIR"), "/cv3_tod_identity.h"));
    /// The Rust half of the boundary, for the entry point's name.
    const FFI: &str = include_str!("ffi.rs");

    /// The body of a C function defined in the shim, from its signature to the closing brace.
    ///
    /// The vfunc bodies are flat, so the first column-0 `}` ends the function.
    fn c_function(signature: &str) -> &'static str {
        let start = SHIM
            .find(signature)
            .unwrap_or_else(|| panic!("the shim should define `{signature}`"));
        let rest = &SHIM[start..];
        let end = rest
            .find("\n}")
            .unwrap_or_else(|| panic!("`{signature}` should end at a column-0 brace"));
        &rest[..end]
    }

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
    fn class_identity_has_one_definition_shared_with_the_shim() {
        // The spec's values. build.rs generates them once, for C and Rust.
        assert_eq!(CLASS_ID, "cv3");
        assert_eq!(FULL_NAME, "Dell/Broadcom ControlVault 3 fingerprint");

        assert!(
            IDENTITY_HEADER.contains(&format!("#define CV3_TOD_CLASS_ID \"{CLASS_ID}\"")),
            "the generated header should define the class id"
        );
        assert!(
            IDENTITY_HEADER.contains(&format!("#define CV3_TOD_FULL_NAME \"{FULL_NAME}\"")),
            "the generated header should define the full name"
        );

        assert!(SHIM.contains("#include \"cv3_tod_identity.h\""));
        assert!(SHIM.contains("device_class->id = CV3_TOD_CLASS_ID;"));
        assert!(SHIM.contains("device_class->full_name = CV3_TOD_FULL_NAME;"));
        assert!(
            !SHIM.contains("device_class->id = \"")
                && !SHIM.contains("device_class->full_name = \""),
            "the shim should use the generated macros, not repeat the literals"
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
    fn shim_stubs_every_vfunc_libfprint_calls_without_a_null_check() {
        // libfprint 1.95 dereferences these three through FpDeviceClass without testing for NULL:
        // fp_device_open and fp_device_close always, and fp_device_enroll once a template print is
        // supplied. A NULL there crashes fprintd, which runs as root.
        for vfunc in ["open", "close", "enroll"] {
            assert!(
                SHIM.contains(&format!("device_class->{vfunc} = cv3_tod_{vfunc};")),
                "`{vfunc}` must be set: libfprint calls it unguarded"
            );
        }
    }

    #[test]
    fn open_fails_with_not_supported_so_a_claim_reports_an_error() {
        let open = c_function("cv3_tod_open (FpDevice *device)");

        assert!(
            open.contains("fpi_device_open_complete (device,"),
            "open must complete the operation it was asked to start"
        );
        assert!(
            open.contains("fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,"),
            "open must fail with NOT_SUPPORTED until the session exists"
        );
        assert!(
            !open.contains("fpi_usb_transfer") && !open.contains("g_usb_"),
            "the milestone performs no USB or session work"
        );
    }

    #[test]
    fn close_always_succeeds() {
        let close = c_function("cv3_tod_close (FpDevice *device)");

        assert!(
            close.contains("fpi_device_close_complete (device, NULL);"),
            "close must complete without an error: this milestone holds nothing"
        );
    }

    #[test]
    fn enrol_fails_with_not_supported_as_defence_in_depth() {
        let enroll = c_function("cv3_tod_enroll (FpDevice *device)");

        assert!(enroll.contains("fpi_device_enroll_complete (device, NULL,"));
        assert!(enroll.contains("FP_DEVICE_ERROR_NOT_SUPPORTED"));
    }

    #[test]
    fn feature_guarded_operations_stay_unimplemented() {
        // libfprint checks both the feature and the vfunc for these, and probe withdraws CAPTURE,
        // so a NULL never reaches them: setting one would imply support this milestone lacks.
        for vfunc in [
            "verify",
            "identify",
            "capture",
            "list",
            "delete",
            "clear_storage",
        ] {
            assert!(
                !SHIM.contains(&format!("device_class->{vfunc}")),
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

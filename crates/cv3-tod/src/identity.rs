//! The plugin's identity as `libfprint` sees it.
//!
//! The class id, the class's full name and the device name are defined once, in `build.rs`: it
//! writes `cv3_tod_identity.h` for the C shim and passes the same values here with
//! `cargo:rustc-env`, so neither side holds a copy that can drift.
//!
//! The USB ids are the core's (`cv3_core::proto`). The shim's C id table cannot import a Rust
//! constant, so it repeats both numbers; the two sides do not read each other. They are pinned to
//! the SPEC's `0a5c:5843` independently: the Rust test on `proto`, and the C harness
//! (`scripts/check-tod-class.sh`) on the live table.

use cv3_core::proto;

/// The driver id, reported by `libfprint` as the device's `driver`.
pub const CLASS_ID: &str = env!("CV3_TOD_CLASS_ID");

/// The human readable name of the driver's class.
pub const FULL_NAME: &str = env!("CV3_TOD_FULL_NAME");

/// The name `libfprint` reports for the device after probe, and `fprintd-list` prints.
pub const DEVICE_NAME: &str = env!("CV3_TOD_DEVICE_NAME");

/// The symbol `libfprint`'s TOD loader resolves in every plugin shared object.
pub const ENTRY_POINT: &str = "fpi_tod_shared_driver_get_type";

/// Vendor of the only sensor this plugin claims.
pub const VENDOR_ID: u16 = proto::VENDOR_ID;

/// Product of the only sensor this plugin claims.
pub const PRODUCT_ID: u16 = proto::PRODUCT_ID;
